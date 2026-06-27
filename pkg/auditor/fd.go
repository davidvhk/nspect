package auditor

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"nspect/pkg/util"
)

// FDInfo details a single file descriptor's type, path, and risk status.
type FDInfo struct {
	FD          int    `json:"fd"`
	Target      string `json:"target"`
	Type        string `json:"type"` // File, Directory, Socket, Pipe, AnonInode, Special
	IsHighRisk  bool   `json:"is_high_risk"`
	Description string `json:"description"`
}

// FDAuditResult represents the output of the FD checks.
type FDAuditResult struct {
	FDs   []FDInfo `json:"fds"`
	Score int      `json:"score"` // 0 to 100
}

// AuditFD inspects `/proc/[pid]/fd` directory to catalog open descriptors and evaluate risks.
func AuditFD(pid int) (*FDAuditResult, error) {
	fdDir := util.ProcPath(pid, "fd")
	entries, err := os.ReadDir(fdDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read file descriptors directory: %w", err)
	}

	var fds []FDInfo
	scoreReduction := 0

	for _, entry := range entries {
		fdNum, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}

		fdLink := filepath.Join(fdDir, entry.Name())
		target, err := os.Readlink(fdLink)
		if err != nil {
			// The file descriptor might have been closed by the target process, skip it
			continue
		}

		fdType := "File"
		isHighRisk := false
		desc := ""

		switch {
		case strings.HasPrefix(target, "socket:"):
			fdType = "Socket"
		case strings.HasPrefix(target, "pipe:"):
			fdType = "Pipe"
		case strings.HasPrefix(target, "anon_inode:"):
			fdType = "AnonInode"
		case target == "/dev/null" || strings.HasPrefix(target, "/dev/pts/"):
			fdType = "Special"
		default:
			// Inspect directory or block device status
			fileInfo, err := os.Stat(fdLink)
			if err == nil {
				if fileInfo.IsDir() {
					fdType = "Directory"
					// Writable or open directory descriptors inside container sandboxes can be abused.
					// We check if it is pointing to a directory that is not standard root, proc, or tmp.
					if target != "/" && target != "/tmp" && !strings.HasPrefix(target, "/proc") && !strings.HasPrefix(target, "/sys") {
						isHighRisk = true
						desc = "Open directory file descriptor pointing to a non-standard directory. If inherited from the host, it can be abused via openat(2) to bypass jail isolation."
						scoreReduction += 15
					}
				}
			}

			targetLower := strings.ToLower(target)
			if strings.Contains(targetLower, "shadow") || strings.Contains(targetLower, "passwd") || strings.Contains(targetLower, "gshadow") {
				isHighRisk = true
				desc = "Open file descriptor accessing a sensitive system user/password database file."
				scoreReduction += 20
			} else if strings.HasPrefix(target, "/dev/sd") || strings.HasPrefix(target, "/dev/nvme") || strings.HasPrefix(target, "/dev/loop") {
				isHighRisk = true
				desc = "Open file descriptor referencing a raw host storage block device."
				scoreReduction += 25
			}
		}

		fds = append(fds, FDInfo{
			FD:          fdNum,
			Target:      target,
			Type:        fdType,
			IsHighRisk:  isHighRisk,
			Description: desc,
		})
	}

	finalScore := 100 - scoreReduction
	if finalScore < 0 {
		finalScore = 0
	}

	return &FDAuditResult{
		FDs:   fds,
		Score: finalScore,
	}, nil
}
