package auditor

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// SysctlCheck details a single sysctl kernel hardening evaluation.
type SysctlCheck struct {
	Key           string `json:"key"`
	Path          string `json:"path"`
	CurrentValue  string `json:"current_value"`
	ExpectedValue string `json:"expected_value"`
	IsSecure      bool   `json:"is_secure"`
	RiskLevel     string `json:"risk_level"` // "Critical", "High", "Medium", "Low", "Info"
	Description   string `json:"description"`
	Remediation   string `json:"remediation"`
}

// KernelRisk details a discovered kernel attack surface risk.
type KernelRisk struct {
	Category    string `json:"category"`
	RiskLevel   string `json:"risk_level"`
	Description string `json:"description"`
}

// KernelAuditResult aggregates all findings for host kernel attack surface audits.
type KernelAuditResult struct {
	Score           int            `json:"score"`
	Sysctls         []SysctlCheck  `json:"sysctls"`
	Risks           []KernelRisk   `json:"risks"`
	Recommendations []string       `json:"recommendations"`
}

// AuditKernelAttackSurface evaluates host sysctl knobs controlling kernel attack surface exposure.
func AuditKernelAttackSurface() (*KernelAuditResult, error) {
	result := &KernelAuditResult{
		Score:           100,
		Sysctls:         make([]SysctlCheck, 0),
		Risks:           make([]KernelRisk, 0),
		Recommendations: make([]string, 0),
	}

	checks := []struct {
		key           string
		path          string
		expected      string
		validateFn    func(val string) (isSecure bool, risk string, desc string, remed string)
	}{
		{
			key:      "kernel.unprivileged_bpf_disabled",
			path:     "/proc/sys/kernel/unprivileged_bpf_disabled",
			expected: "1 or 2",
			validateFn: func(val string) (bool, string, string, string) {
				v, _ := strconv.Atoi(strings.TrimSpace(val))
				if v >= 1 {
					return true, "Low", "Unprivileged eBPF program loading is disabled.", ""
				}
				return false, "High", "Unprivileged local users can load eBPF programs, exposing the kernel to JIT spray, memory corruption, and container breakout exploits.", "sysctl -w kernel.unprivileged_bpf_disabled=1"
			},
		},
		{
			key:      "net.core.bpf_jit_harden",
			path:     "/proc/sys/net/core/bpf_jit_harden",
			expected: "1 or 2",
			validateFn: func(val string) (bool, string, string, string) {
				v, _ := strconv.Atoi(strings.TrimSpace(val))
				if v >= 1 {
					return true, "Low", "eBPF JIT compiler hardening is enabled.", ""
				}
				return false, "High", "eBPF JIT hardening is disabled. Attackers can abuse JIT compilation to construct executable exploit payloads in kernel memory.", "sysctl -w net.core.bpf_jit_harden=2"
			},
		},
		{
			key:      "kernel.kptr_restrict",
			path:     "/proc/sys/kernel/kptr_restrict",
			expected: "1 or 2",
			validateFn: func(val string) (bool, string, string, string) {
				v, _ := strconv.Atoi(strings.TrimSpace(val))
				if v >= 1 {
					return true, "Low", "Kernel symbol pointer address leaks via /proc are restricted.", ""
				}
				return false, "High", "Kernel symbol addresses (%pK) are exposed in /proc/kallsyms. Attackers can read raw kernel memory addresses to bypass KASLR.", "sysctl -w kernel.kptr_restrict=2"
			},
		},
		{
			key:      "kernel.dmesg_restrict",
			path:     "/proc/sys/kernel/dmesg_restrict",
			expected: "1",
			validateFn: func(val string) (bool, string, string, string) {
				v, _ := strconv.Atoi(strings.TrimSpace(val))
				if v >= 1 {
					return true, "Low", "Access to kernel ring buffer (dmesg) is restricted to privileged CAP_SYSLOG users.", ""
				}
				return false, "Medium", "Unprivileged users can read dmesg logs, leaking kernel addresses, oops stack traces, and device details.", "sysctl -w kernel.dmesg_restrict=1"
			},
		},
		{
			key:      "kernel.yama.ptrace_scope",
			path:     "/proc/sys/kernel/yama/ptrace_scope",
			expected: "1, 2, or 3",
			validateFn: func(val string) (bool, string, string, string) {
				v, _ := strconv.Atoi(strings.TrimSpace(val))
				if v >= 1 {
					return true, "Low", "YAMA ptrace restrictions are enforced (classic cross-process ptrace prohibited).", ""
				}
				return false, "High", "YAMA ptrace restriction is set to classic (0). Any process with the same UID can attach ptrace and inject code into other processes.", "sysctl -w kernel.yama.ptrace_scope=1"
			},
		},
		{
			key:      "kernel.unprivileged_userns_clone",
			path:     "/proc/sys/kernel/unprivileged_userns_clone",
			expected: "0",
			validateFn: func(val string) (bool, string, string, string) {
				v, _ := strconv.Atoi(strings.TrimSpace(val))
				if v == 0 {
					return true, "Low", "Unprivileged creation of user namespaces is disabled.", ""
				}
				return false, "Medium", "Unprivileged users can clone new user namespaces, expanding kernel attack surface for namespace-based LPE exploits.", "sysctl -w kernel.unprivileged_userns_clone=0"
			},
		},
		{
			key:      "user.max_user_namespaces",
			path:     "/proc/sys/user/max_user_namespaces",
			expected: "> 0 (for containers) or 0 (hardened host)",
			validateFn: func(val string) (bool, string, string, string) {
				v, err := strconv.Atoi(strings.TrimSpace(val))
				if err != nil {
					return true, "Info", "Property unavailable.", ""
				}
				if v > 0 && v < 1000000 {
					return true, "Low", fmt.Sprintf("User namespace quota is active (%d max user namespaces).", v), ""
				}
				if v == 0 {
					return true, "Low", "User namespace creation is disabled (max_user_namespaces=0).", ""
				}
				return true, "Info", fmt.Sprintf("Max user namespaces set to %d.", v), ""
			},
		},
		{
			key:      "fs.protected_symlinks",
			path:     "/proc/sys/fs/protected_symlinks",
			expected: "1",
			validateFn: func(val string) (bool, string, string, string) {
				v, _ := strconv.Atoi(strings.TrimSpace(val))
				if v >= 1 {
					return true, "Low", "Symlink follow protections in sticky world-writable directories (/tmp) are enabled.", ""
				}
				return false, "Medium", "Symlink protection is disabled. Attackers can exploit symlink races in /tmp to trick privileged processes into truncating or overwriting host files.", "sysctl -w fs.protected_symlinks=1"
			},
		},
		{
			key:      "fs.protected_hardlinks",
			path:     "/proc/sys/fs/protected_hardlinks",
			expected: "1",
			validateFn: func(val string) (bool, string, string, string) {
				v, _ := strconv.Atoi(strings.TrimSpace(val))
				if v >= 1 {
					return true, "Low", "Hardlink creation protections across different file owners are enabled.", ""
				}
				return false, "Medium", "Hardlink protection is disabled. Attackers can create hardlinks to sensitive system files to bypass file permissions.", "sysctl -w fs.protected_hardlinks=1"
			},
		},
		{
			key:      "fs.protected_fifos",
			path:     "/proc/sys/fs/protected_fifos",
			expected: "1 or 2",
			validateFn: func(val string) (bool, string, string, string) {
				v, _ := strconv.Atoi(strings.TrimSpace(val))
				if v >= 1 {
					return true, "Low", "FIFO pipe protections in sticky world-writable directories are enabled.", ""
				}
				return false, "Low", "FIFO protection in sticky world-writable directories is disabled. Attackers can exploit FIFO pipes for data hijacking.", "sysctl -w fs.protected_fifos=1"
			},
		},
	}

	penaltyMap := map[string]int{
		"Critical": 25,
		"High":     15,
		"Medium":   10,
		"Low":      5,
		"Info":     0,
	}

	for _, c := range checks {
		valData, err := os.ReadFile(c.path)
		if err != nil {
			// Sysctl endpoint does not exist on this kernel version or architecture
			continue
		}
		valStr := strings.TrimSpace(string(valData))
		isSecure, riskLevel, desc, remed := c.validateFn(valStr)

		checkObj := SysctlCheck{
			Key:           c.key,
			Path:          c.path,
			CurrentValue:  valStr,
			ExpectedValue: c.expected,
			IsSecure:      isSecure,
			RiskLevel:     riskLevel,
			Description:   desc,
			Remediation:   remed,
		}

		result.Sysctls = append(result.Sysctls, checkObj)

		if !isSecure {
			penalty := penaltyMap[riskLevel]
			result.Score -= penalty
			if result.Score < 0 {
				result.Score = 0
			}

			result.Risks = append(result.Risks, KernelRisk{
				Category:    "Kernel Sysctl Hardening",
				RiskLevel:   riskLevel,
				Description: fmt.Sprintf("%s: %s (Current value: %s, Recommended: %s)", c.key, desc, valStr, c.expected),
			})

			if remed != "" {
				result.Recommendations = append(result.Recommendations, remed)
			}
		}
	}

	// Clean up duplicate recommendations
	result.Recommendations = uniqueStrings(result.Recommendations)
	return result, nil
}

func uniqueStrings(input []string) []string {
	seen := make(map[string]bool)
	var output []string
	for _, item := range input {
		if !seen[item] {
			seen[item] = true
			output = append(output, item)
		}
	}
	return output
}
