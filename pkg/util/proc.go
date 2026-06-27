package util

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// ProcPath returns the absolute path under /proc for a given pid and subpaths.
func ProcPath(pid int, subpaths ...string) string {
	parts := append([]string{"/proc", strconv.Itoa(pid)}, subpaths...)
	return filepath.Join(parts...)
}

// ProcessExists checks if a process with the given PID is running.
func ProcessExists(pid int) bool {
	if pid <= 0 {
		return false
	}
	_, err := os.Stat(ProcPath(pid))
	return err == nil
}

// GetProcessName retrieves the name of the process from /proc/[pid]/comm.
func GetProcessName(pid int) (string, error) {
	data, err := os.ReadFile(ProcPath(pid, "comm"))
	if err != nil {
		// Fallback to cmdline
		cmdline, cmdErr := os.ReadFile(ProcPath(pid, "cmdline"))
		if cmdErr != nil || len(cmdline) == 0 {
			return "", err
		}
		// cmdline uses null bytes as separators
		parts := strings.Split(string(cmdline), "\x00")
		if len(parts) > 0 && parts[0] != "" {
			return filepath.Base(parts[0]), nil
		}
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

// GetCmdline retrieves the full command line of the process.
func GetCmdline(pid int) (string, error) {
	data, err := os.ReadFile(ProcPath(pid, "cmdline"))
	if err != nil {
		return "", err
	}
	if len(data) == 0 {
		return "", nil
	}
	parts := strings.Split(string(data), "\x00")
	// Clean up empty trailing fields
	var cleanParts []string
	for _, p := range parts {
		if p != "" {
			cleanParts = append(cleanParts, p)
		}
	}
	return strings.Join(cleanParts, " "), nil
}

// ParseKeyValuePair parses a file containing key-value pairs (like status) separated by a colon.
func ParseKeyValuePair(filePath string) (map[string]string, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	result := make(map[string]string)
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])
		result[key] = val
	}
	return result, nil
}
