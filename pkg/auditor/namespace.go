package auditor

import (
	"fmt"
	"os"
	"regexp"
	"strconv"

	"nspect/pkg/util"
)

// NamespaceInfo holds the audit details for a single Linux namespace.
type NamespaceInfo struct {
	Name             string `json:"name"`
	TargetInode      uint64 `json:"target_inode"`
	HostInode        uint64 `json:"host_inode"`
	IsSharedWithHost bool   `json:"is_shared_with_host"`
	RiskLevel        string `json:"risk_level"`
	Description      string `json:"description"`
}

// NamespaceAuditResult holds the collection of namespace audits.
type NamespaceAuditResult struct {
	Namespaces []NamespaceInfo `json:"namespaces"`
	Score      int             `json:"score"` // 0 to 100, where 100 is perfectly isolated
}

// Inode regex to parse namespace link format e.g. "mnt:[4026531905]"
var inodeRegex = regexp.MustCompile(`^.+:\[(\d+)\]$`)

// GetNamespaceInode retrieves the inode of a specific namespace for a given PID.
func GetNamespaceInode(pid int, nsName string) (uint64, error) {
	nsPath := util.ProcPath(pid, "ns", nsName)
	link, err := os.Readlink(nsPath)
	if err != nil {
		return 0, err
	}

	matches := inodeRegex.FindStringSubmatch(link)
	if len(matches) != 2 {
		return 0, fmt.Errorf("unexpected namespace link format: %s", link)
	}

	inode, err := strconv.ParseUint(matches[1], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("failed to parse inode integer: %w", err)
	}

	return inode, nil
}

// AuditNamespaces compares namespaces of the target PID against host PID 1.
func AuditNamespaces(targetPID int) (*NamespaceAuditResult, error) {
	nsTypes := []string{"cgroup", "ipc", "mnt", "net", "pid", "user", "uts"}
	
	// Add "time" namespace if supported by kernel / procfs
	if _, err := os.Stat(util.ProcPath(targetPID, "ns", "time")); err == nil {
		nsTypes = append(nsTypes, "time")
	}

	var infos []NamespaceInfo
	scoreReduction := 0
	maxReduction := 100

	for _, ns := range nsTypes {
		targetInode, err := GetNamespaceInode(targetPID, ns)
		if err != nil {
			// Some older kernels or configurations might not have all namespaces
			continue
		}

		hostInode, err := GetNamespaceInode(1, ns)
		if err != nil {
			// Fallback to our own process namespace
			hostInode, err = GetNamespaceInode(os.Getpid(), ns)
			if err != nil {
				hostInode = 0
			}
		}

		isShared := false
		if hostInode != 0 && targetInode == hostInode {
			isShared = true
		}

		risk := "Info"
		desc := ""

		switch ns {
		case "mnt":
			if isShared {
				risk = "Critical"
				desc = "Shares mount namespace with host. The container can see and potentially manipulate all host mounts."
				scoreReduction += 30
			} else {
				desc = "Mount namespace is isolated."
			}
		case "pid":
			if isShared {
				risk = "High"
				desc = "Shares PID namespace with host. The container can view, trace, and terminate host processes."
				scoreReduction += 25
			} else {
				desc = "Process namespace is isolated."
			}
		case "net":
			if isShared {
				risk = "High"
				desc = "Shares Network namespace with host. The container shares host interfaces, socket tables, and can sniff network traffic."
				scoreReduction += 25
			} else {
				desc = "Network namespace is isolated."
			}
		case "ipc":
			if isShared {
				risk = "Medium"
				desc = "Shares IPC namespace with host. The container can access host shared memory, semaphores, and message queues."
				scoreReduction += 15
			} else {
				desc = "IPC namespace is isolated."
			}
		case "uts":
			if isShared {
				risk = "Low"
				desc = "Shares UTS namespace with host. The container shares the host hostname, allowing modification."
				scoreReduction += 5
			} else {
				desc = "UTS (hostname) namespace is isolated."
			}
		case "user":
			if isShared {
				// Running in host user namespace. 
				// This is only Critical/High if running as UID 0. We will combine this with UID check in security auditor,
				// but namespace sharing itself indicates lack of user namespace isolation.
				risk = "Medium"
				desc = "Shares User namespace with host. No UID/GID virtualization is active."
				scoreReduction += 10
			} else {
				desc = "User namespace is isolated (rootless/virtualized UID space)."
			}
		case "cgroup":
			if isShared {
				risk = "Low"
				desc = "Shares cgroup namespace with host. May leak host cgroup layout information."
				scoreReduction += 5
			} else {
				desc = "Cgroup namespace is isolated."
			}
		case "time":
			if isShared {
				risk = "Low"
				desc = "Shares time namespace with host."
			} else {
				desc = "Time namespace is isolated."
			}
		}

		infos = append(infos, NamespaceInfo{
			Name:             ns,
			TargetInode:      targetInode,
			HostInode:        hostInode,
			IsSharedWithHost: isShared,
			RiskLevel:        risk,
			Description:      desc,
		})
	}

	finalScore := 100 - scoreReduction
	if finalScore < 0 {
		finalScore = 0
	}
	if finalScore > maxReduction {
		finalScore = maxReduction
	}

	return &NamespaceAuditResult{
		Namespaces: infos,
		Score:      finalScore,
	}, nil
}
