package auditor

import (
	"os"
	"strconv"

	"nspect/pkg/util"
)

// IsolatedProcess represents a process running in a mount namespace separate from the host init.
type IsolatedProcess struct {
	PID         int    `json:"pid"`
	Name        string `json:"name"`
	Cmdline     string `json:"cmdline"`
	MountInode  uint64 `json:"mount_inode"`
}

// FindIsolatedProcesses scans /proc to find all processes running in isolated mount namespaces.
func FindIsolatedProcesses() ([]IsolatedProcess, error) {
	hostMntNS, err := GetNamespaceInode(1, "mnt")
	if err != nil {
		// Fallback to our own process namespace
		hostMntNS, err = GetNamespaceInode(os.Getpid(), "mnt")
		if err != nil {
			return nil, err
		}
	}

	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}

	var processes []IsolatedProcess
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		pid, err := strconv.Atoi(entry.Name())
		// Skip non-numeric directories, host init, and kernel threads
		if err != nil || pid <= 1 {
			continue
		}

		targetMntNS, err := GetNamespaceInode(pid, "mnt")
		if err != nil {
			// May fail due to process termination or permission limits
			continue
		}

		if targetMntNS != hostMntNS {
			name, _ := util.GetProcessName(pid)
			cmdline, _ := util.GetCmdline(pid)
			processes = append(processes, IsolatedProcess{
				PID:        pid,
				Name:       name,
				Cmdline:    cmdline,
				MountInode: targetMntNS,
			})
		}
	}

	return processes, nil
}
