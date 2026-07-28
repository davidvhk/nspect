package auditor

import (
	"os"
	"strconv"
	"sync"

	"nspect/pkg/util"
)

// IsolatedProcess represents a process running in a mount namespace separate from the host init.
type IsolatedProcess struct {
	PID        int    `json:"pid"`
	Name       string `json:"name"`
	Cmdline    string `json:"cmdline"`
	MountInode uint64 `json:"mount_inode"`
	Score      int    `json:"score"`
}

// FindIsolatedProcesses scans /proc to find isolated processes (or active user/service processes if none are isolated).
func FindIsolatedProcesses() ([]IsolatedProcess, error) {
	hostMntNS, _ := GetNamespaceInode(1, "mnt")
	hostNetNS, _ := GetNamespaceInode(1, "net")
	hostPidNS, _ := GetNamespaceInode(1, "pid")
	hostUserNS, _ := GetNamespaceInode(1, "user")
	hostIpcNS, _ := GetNamespaceInode(1, "ipc")

	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}

	var isolatedProcesses []IsolatedProcess
	var allProcesses []IsolatedProcess

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

		procObj := IsolatedProcess{
			PID:        pid,
			Name:       name,
			Cmdline:    cmdline,
			MountInode: targetMntNS,
			Score:      100,
		}

		allProcesses = append(allProcesses, procObj)
		if isIsolated {
			isolatedProcesses = append(isolatedProcesses, procObj)
		}
	}

	targetList := allProcesses
	if len(isolatedProcesses) > 0 {
		targetList = isolatedProcesses
	}

	// Calculate exact security scores concurrently for all PID cards
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 16)

	for i := range targetList {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			if rep, err := GenerateReport(targetList[idx].PID, targetList[idx].Name, targetList[idx].Cmdline, true); err == nil {
				targetList[idx].Score = rep.OverallScore
			}
		}(i)
	}
	wg.Wait()

	return targetList, nil
}
