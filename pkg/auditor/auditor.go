package auditor

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"sync"

	"nspect/pkg/util"
)

// ErrPermissionRestricted indicates that the auditor does not have sufficient permissions (root/CAP_SYS_PTRACE) to scan host namespaces.
var ErrPermissionRestricted = errors.New("insufficient permissions to inspect namespaces in /proc (requires root privileges or CAP_SYS_PTRACE)")

// IsolatedProcess represents a process running in a mount namespace separate from the host init.
type IsolatedProcess struct {
	PID        int    `json:"pid"`
	Name       string `json:"name"`
	Cmdline    string `json:"cmdline"`
	MountInode uint64 `json:"mount_inode"`
	Score      int    `json:"score"`
}

// FindIsolatedProcesses scans /proc to find isolated processes running in separate namespaces.
// If running without root/CAP_SYS_PTRACE permissions, it returns the calling self process
// along with ErrPermissionRestricted so callers can audit the local container context.
func FindIsolatedProcesses() ([]IsolatedProcess, error) {
	hostMntNS, errMnt := GetNamespaceInode(1, "mnt")
	hostNetNS, errNet := GetNamespaceInode(1, "net")
	hostPidNS, errPid := GetNamespaceInode(1, "pid")
	hostUserNS, errUser := GetNamespaceInode(1, "user")
	hostIpcNS, errIpc := GetNamespaceInode(1, "ipc")

	// If reading host namespaces from PID 1 failed due to permission denial
	if hostMntNS == 0 && hostNetNS == 0 && hostPidNS == 0 {
		var firstErr error
		for _, err := range []error{errMnt, errNet, errPid, errUser, errIpc} {
			if err != nil {
				firstErr = err
				break
			}
		}
		if firstErr != nil {
			selfPID := os.Getpid()
			selfName, _ := util.GetProcessName(selfPID)
			selfCmdline, _ := util.GetCmdline(selfPID)
			selfMntNS, _ := GetNamespaceInode(selfPID, "mnt")
			selfScore := 100
			if rep, err := GenerateReport(selfPID, selfName, selfCmdline, true); err == nil {
				selfScore = rep.OverallScore
			}

			selfProcess := IsolatedProcess{
				PID:        selfPID,
				Name:       selfName,
				Cmdline:    selfCmdline,
				MountInode: selfMntNS,
				Score:      selfScore,
			}
			return []IsolatedProcess{selfProcess}, fmt.Errorf("%w: %v", ErrPermissionRestricted, firstErr)
		}
	}

	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}

	var isolatedProcesses []IsolatedProcess

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		pid, err := strconv.Atoi(entry.Name())
		// Skip non-numeric directories, host init, and kernel threads
		if err != nil || pid <= 1 {
			continue
		}

		name, _ := util.GetProcessName(pid)
		cmdline, _ := util.GetCmdline(pid)
		if name == "" {
			continue
		}

		targetMntNS, _ := GetNamespaceInode(pid, "mnt")
		targetNetNS, _ := GetNamespaceInode(pid, "net")
		targetPidNS, _ := GetNamespaceInode(pid, "pid")
		targetUserNS, _ := GetNamespaceInode(pid, "user")
		targetIpcNS, _ := GetNamespaceInode(pid, "ipc")

		isIsolated := (hostMntNS != 0 && targetMntNS != 0 && targetMntNS != hostMntNS) ||
			(hostNetNS != 0 && targetNetNS != 0 && targetNetNS != hostNetNS) ||
			(hostPidNS != 0 && targetPidNS != 0 && targetPidNS != hostPidNS) ||
			(hostUserNS != 0 && targetUserNS != 0 && targetUserNS != hostUserNS) ||
			(hostIpcNS != 0 && targetIpcNS != 0 && targetIpcNS != hostIpcNS)

		if isIsolated {
			isolatedProcesses = append(isolatedProcesses, IsolatedProcess{
				PID:        pid,
				Name:       name,
				Cmdline:    cmdline,
				MountInode: targetMntNS,
				Score:      100,
			})
		}
	}

	// Calculate exact security scores concurrently for all isolated process cards
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 16)

	for i := range isolatedProcesses {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			if rep, err := GenerateReport(isolatedProcesses[idx].PID, isolatedProcesses[idx].Name, isolatedProcesses[idx].Cmdline, true); err == nil {
				isolatedProcesses[idx].Score = rep.OverallScore
			}
		}(i)
	}
	wg.Wait()

	return isolatedProcesses, nil
}
