package auditor

import (
	"fmt"
	"strconv"
	"strings"

	"nspect/pkg/util"
)

// CapabilityMap lists all standard Linux capabilities by bit position.
var CapabilityMap = map[int]string{
	0:  "CAP_CHOWN",
	1:  "CAP_DAC_OVERRIDE",
	2:  "CAP_DAC_READ_SEARCH",
	3:  "CAP_FOWNER",
	4:  "CAP_FSETID",
	5:  "CAP_KILL",
	6:  "CAP_SETGID",
	7:  "CAP_SETUID",
	8:  "CAP_SETPCAP",
	9:  "CAP_LINUX_IMMUTABLE",
	10: "CAP_NET_BIND_SERVICE",
	11: "CAP_NET_BROADCAST",
	12: "CAP_NET_ADMIN",
	13: "CAP_NET_RAW",
	14: "CAP_IPC_LOCK",
	15: "CAP_IPC_OWNER",
	16: "CAP_SYS_MODULE",
	17: "CAP_SYS_RAWIO",
	18: "CAP_SYS_CHROOT",
	19: "CAP_SYS_PTRACE",
	20: "CAP_SYS_PACCT",
	21: "CAP_SYS_ADMIN",
	22: "CAP_SYS_BOOT",
	23: "CAP_SYS_NICE",
	24: "CAP_SYS_RESOURCE",
	25: "CAP_SYS_TIME",
	26: "CAP_SYS_TTY_CONFIG",
	27: "CAP_MKNOD",
	28: "CAP_LEASE",
	29: "CAP_AUDIT_WRITE",
	30: "CAP_AUDIT_CONTROL",
	31: "CAP_SETFCAP",
	32: "CAP_MAC_OVERRIDE",
	33: "CAP_MAC_ADMIN",
	34: "CAP_SYSLOG",
	35: "CAP_WAKE_ALARM",
	36: "CAP_BLOCK_SUSPEND",
	37: "CAP_AUDIT_READ",
	38: "CAP_PERFMON",
	39: "CAP_BPF",
	40: "CAP_CHECKPOINT_RESTORE",
}

// CapabilityRisk defines security implications of sensitive capabilities.
type CapabilityRisk struct {
	Name        string `json:"name"`
	RiskLevel   string `json:"risk_level"` // Critical, High, Medium, Low
	Description string `json:"description"`
}

// CapabilityRiskDatabase holds the risks for known capabilities.
var CapabilityRiskDatabase = map[string]CapabilityRisk{
	"CAP_SYS_ADMIN": {
		Name:        "CAP_SYS_ADMIN",
		RiskLevel:   "Critical",
		Description: "The 'new root' capability. Overloaded with administrative permissions. Allows mounting/unmounting filesystems, configuring namespaces, loading security modules, and bypasses almost all permission checks. Frequently used in container breakout attacks.",
	},
	"CAP_SYS_MODULE": {
		Name:        "CAP_SYS_MODULE",
		RiskLevel:   "Critical",
		Description: "Allows loading and unloading of arbitrary kernel modules. Can be used to inject malicious code directly into host kernel space (LKM rootkits), fully bypassing container isolation.",
	},
	"CAP_SYS_RAWIO": {
		Name:        "CAP_SYS_RAWIO",
		RiskLevel:   "High",
		Description: "Allows direct access to physical input/output ports (I/O) and raw memory (e.g. /dev/mem, /dev/kmem). Can be abused to read or write host kernel memory.",
	},
	"CAP_SYS_PTRACE": {
		Name:        "CAP_SYS_PTRACE",
		RiskLevel:   "High",
		Description: "Allows tracing and debugging arbitrary processes using ptrace(2). Can be used to inspect memory and inject malicious shellcode into other processes.",
	},
	"CAP_SYS_CHROOT": {
		Name:        "CAP_SYS_CHROOT",
		RiskLevel:   "Medium",
		Description: "Allows usage of chroot(2) to change the root directory. If combined with other misconfigurations or file descriptors leaks, chroot can be used to escape directory jails.",
	},
	"CAP_SYS_BOOT": {
		Name:        "CAP_SYS_BOOT",
		RiskLevel:   "High",
		Description: "Allows calling reboot(2) and loading a new kernel via kexec_load(2). Can lead to denial of service or execution of unsigned kernels.",
	},
	"CAP_NET_ADMIN": {
		Name:        "CAP_NET_ADMIN",
		RiskLevel:   "High",
		Description: "Allows modification of network interfaces, routing tables, firewall rules (iptables/nftables), and traffic shaping. Can be used to redirect, intercept, or spoof container/host network traffic.",
	},
	"CAP_NET_RAW": {
		Name:        "CAP_NET_RAW",
		RiskLevel:   "Medium",
		Description: "Allows opening raw sockets. Bypasses local port binding rules and allows packet sniffing or custom packet generation (ARP spoofing, packet injection). Often dropped in hardened environments.",
	},
	"CAP_DAC_OVERRIDE": {
		Name:        "CAP_DAC_OVERRIDE",
		RiskLevel:   "High",
		Description: "Bypasses all file read, write, and execute permission checks (discretionary access control). Allows reading/writing sensitive files on host/container filesystems.",
	},
	"CAP_DAC_READ_SEARCH": {
		Name:        "CAP_DAC_READ_SEARCH",
		RiskLevel:   "Medium",
		Description: "Bypasses directory search and file read checks. Allows reading sensitive configuration files, system logs, or cryptographic keys.",
	},
	"CAP_FOWNER": {
		Name:        "CAP_FOWNER",
		RiskLevel:   "Medium",
		Description: "Bypasses permission checks on operations that normally require the file owner's UID to match (e.g., chmod, utime). Can change permissions of critical system files.",
	},
	"CAP_KILL": {
		Name:        "CAP_KILL",
		RiskLevel:   "Medium",
		Description: "Bypasses permission checks for sending signals to processes. Can kill process trees of other containers or host services.",
	},
	"CAP_SETUID": {
		Name:        "CAP_SETUID",
		RiskLevel:   "Medium",
		Description: "Allows changing the process UID arbitrarily. Useful for privilege escalation if a service is compromised.",
	},
	"CAP_SETGID": {
		Name:        "CAP_SETGID",
		RiskLevel:   "Medium",
		Description: "Allows changing the process GID arbitrarily. Useful for gaining access to restricted group files.",
	},
	"CAP_SETPCAP": {
		Name:        "CAP_SETPCAP",
		RiskLevel:   "Medium",
		Description: "Allows modifying capability bounding sets of other processes or transferring permissions. Can be abused to escalate privileges.",
	},
	"CAP_MKNOD": {
		Name:        "CAP_MKNOD",
		RiskLevel:   "High",
		Description: "Allows creating special files (devices) using mknod(2). If a container has this capability and has write access to a host directory or loop device, an attacker can create host raw disk device nodes (e.g., sda) and read/write host storage directly.",
	},
	"CAP_BPF": {
		Name:        "CAP_BPF",
		RiskLevel:   "High",
		Description: "Allows running privileged eBPF operations. Can trace kernel memory, inspect traffic, or execute code inside kernel contexts.",
	},
	"CAP_PERFMON": {
		Name:        "CAP_PERFMON",
		RiskLevel:   "Medium",
		Description: "Allows performance monitoring and tracing. Can leak sensitive data via side-channel analysis of CPU registers and execution paths.",
	},
}

// CapabilitySet represents parsed capability flags for a process.
type CapabilitySet struct {
	Inheritable []string `json:"inheritable"`
	Permitted   []string `json:"permitted"`
	Effective   []string `json:"effective"`
	Bounding    []string `json:"bounding"`
	Ambient     []string `json:"ambient"`
}

// CapabilityAuditResult holds the full audit of process capabilities.
type CapabilityAuditResult struct {
	Sets          CapabilitySet    `json:"sets"`
	HighRiskCaps  []CapabilityRisk `json:"high_risk_caps"`
	Score         int              `json:"score"` // 0 to 100
}

// ParseCapabilityMask converts a 64-bit hex capability bitmask to slice of capability names.
func ParseCapabilityMask(maskHex string) ([]string, error) {
	maskHex = strings.TrimPrefix(maskHex, "0x")
	maskHex = strings.TrimSpace(maskHex)
	if maskHex == "" {
		return nil, fmt.Errorf("empty capability mask")
	}

	val, err := strconv.ParseUint(maskHex, 16, 64)
	if err != nil {
		return nil, fmt.Errorf("failed to parse capability hex '%s': %w", maskHex, err)
	}

	var caps []string
	for bit, name := range CapabilityMap {
		if (val & (1 << uint(bit))) != 0 {
			caps = append(caps, name)
		}
	}
	return caps, nil
}

// AuditCapabilities reads and audits capabilities of a given PID from /proc/[pid]/status.
func AuditCapabilities(pid int) (*CapabilityAuditResult, error) {
	statusPath := util.ProcPath(pid, "status")
	kv, err := util.ParseKeyValuePair(statusPath)
	if err != nil {
		return nil, fmt.Errorf("failed to parse process status: %w", err)
	}

	capKeys := []string{"CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"}
	capsParsed := make(map[string][]string)

	for _, key := range capKeys {
		val, exists := kv[key]
		if !exists {
			// Older kernels might not have CapAmb, etc.
			capsParsed[key] = []string{}
			continue
		}
		lst, err := ParseCapabilityMask(val)
		if err != nil {
			return nil, fmt.Errorf("failed to parse %s: %w", key, err)
		}
		capsParsed[key] = lst
	}

	capSet := CapabilitySet{
		Inheritable: capsParsed["CapInh"],
		Permitted:   capsParsed["CapPrm"],
		Effective:   capsParsed["CapEff"],
		Bounding:    capsParsed["CapBnd"],
		Ambient:     capsParsed["CapAmb"],
	}

	// Parse Uid to check if process is running as root
	isRoot := false
	uidVal, hasUID := kv["Uid"]
	if hasUID {
		fields := strings.Fields(uidVal)
		if len(fields) >= 2 {
			euid, _ := strconv.Atoi(fields[1])
			if euid == 0 {
				isRoot = true
			}
		}
	}

	var highRiskCaps []CapabilityRisk
	scoreReduction := 0
	seen := make(map[string]bool)

	// If the process is running as root, we audit both Effective and Bounding capabilities,
	// since root processes can easily activate capabilities in their bounding set.
	// If the process is non-root, we only audit active (Effective/Permitted) capabilities.
	var targetCaps []string
	if isRoot {
		targetCaps = append(capSet.Effective, capSet.Bounding...)
	} else {
		targetCaps = append(capSet.Effective, capSet.Permitted...)
	}

	for _, capName := range targetCaps {
		if seen[capName] {
			continue
		}
		seen[capName] = true

		if risk, exists := CapabilityRiskDatabase[capName]; exists {
			highRiskCaps = append(highRiskCaps, risk)
			switch risk.RiskLevel {
			case "Critical":
				scoreReduction += 30
			case "High":
				scoreReduction += 20
			case "Medium":
				scoreReduction += 10
			case "Low":
				scoreReduction += 3
			}
		}
	}

	finalScore := 100 - scoreReduction
	if finalScore < 0 {
		finalScore = 0
	}

	return &CapabilityAuditResult{
		Sets:         capSet,
		HighRiskCaps: highRiskCaps,
		Score:        finalScore,
	}, nil
}
