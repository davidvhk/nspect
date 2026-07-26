package auditor

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"nspect/pkg/util"
)

const (
	ptraceSeccompGetFilter = 0x420c
	ptraceAttach           = 16
	ptraceDetach           = 17

	// Seccomp return action masks and values
	seccompRetActionFull  uint32 = 0xffff0000
	seccompRetKillThread  uint32 = 0x00000000
	seccompRetTrap        uint32 = 0x00030000
	seccompRetErrno       uint32 = 0x00050000
	seccompRetUserNotif   uint32 = 0x7fc00000
	seccompRetTrace       uint32 = 0x7fe00000
	seccompRetLog         uint32 = 0x7ffc0000
	seccompRetAllow       uint32 = 0x7fff0000
	seccompRetKillProcess uint32 = 0x80000000

	// BPF Instruction Opcodes
	bpfLd  = 0x00
	bpfW   = 0x00
	bpfAbs = 0x20
	bpfJmp = 0x05
	bpfJeq = 0x10
	bpfK   = 0x00
	bpfRet = 0x06
)

// SockFilter matches Linux struct sock_filter (8 bytes)
type SockFilter struct {
	Code uint16
	Jt   uint8
	Jf   uint8
	K    uint32
}

// SeccompSyscallCheck details an audited system call
type SeccompSyscallCheck struct {
	Name          string `json:"name"`
	Syscall       int    `json:"syscall"`
	Status        string `json:"status"`         // "Blocked", "Allowed", "Filtered"
	ActionDetails string `json:"action_details,omitempty"` // Exact BPF return action, e.g. "SECCOMP_RET_ERRNO (EPERM)"
	Risk          string `json:"risk"`
}

// SeccompAuditDetails contains complete Seccomp deep analysis findings
type SeccompAuditDetails struct {
	Mode                int                   `json:"mode"`
	ModeDesc            string                `json:"mode_desc"`
	FilterCount         int                   `json:"filter_count"`
	HasUserNotifier     bool                  `json:"has_user_notifier"`
	NotifierFD          int                   `json:"notifier_fd,omitempty"`
	PolicyArchitecture  string                `json:"policy_architecture,omitempty"`  // "Default-Deny (Whitelist)" or "Default-Allow (Blacklist)"
	InstructionCount    int                   `json:"instruction_count,omitempty"`    // Total BPF filter bytecode instructions
	DefaultReturnAction string                `json:"default_return_action,omitempty"`// e.g. "SECCOMP_RET_KILL_PROCESS"
	ActionCounts        map[string]int        `json:"action_counts,omitempty"`         // Distribution of return actions (ALLOW, ERRNO, etc.)
	HasArgInspection    bool                  `json:"has_arg_inspection"`             // True if argument filtering is present
	ArgInspectionCount  int                   `json:"arg_inspection_count,omitempty"` // Count of argument checking instructions
	ValidatedArchName   string                `json:"validated_arch_name,omitempty"`  // e.g. "AUDIT_ARCH_X86_64"
	InspectedViaPtrace  bool                  `json:"inspected_via_ptrace"`
	InspectionNotes     string                `json:"inspection_notes,omitempty"`
	ArchValidated       bool                  `json:"arch_validated"`                 // True if AUDIT_ARCH check is present
	ArchBypassRisk      bool                  `json:"arch_bypass_risk"`              // True if 32-bit / ABI bypass is possible
	ProfileFingerprint  string                `json:"profile_fingerprint,omitempty"`  // Docker, Podman, Systemd, Strict, Custom
	MetadataFlags       []string              `json:"metadata_flags,omitempty"`       // TSYNC, LOG, SPEC_ALLOW
	ViolationsDetected  int                   `json:"violations_detected,omitempty"`
	RecentViolations    []string              `json:"recent_violations,omitempty"`
	AuditedSyscalls     []SeccompSyscallCheck `json:"audited_syscalls,omitempty"`
	Risks               []string              `json:"risks,omitempty"`
	Recommendations     []string              `json:"recommendations,omitempty"`
}

// Critical high-risk system calls to evaluate during Seccomp BPF inspection
type highRiskSyscall struct {
	Name         string
	X86Syscall   int
	Arm64Syscall int
	RiskMsg      string
}

var targetHighRiskSyscalls = []highRiskSyscall{
	{
		Name:         "unshare",
		X86Syscall:   272,
		Arm64Syscall: 97,
		RiskMsg:      "User/Mount namespace disassociation (container isolation escape vector)",
	},
	{
		Name:         "clone3",
		X86Syscall:   435,
		Arm64Syscall: 435,
		RiskMsg:      "Extensible process creation with namespace flags",
	},
	{
		Name:         "bpf",
		X86Syscall:   321,
		Arm64Syscall: 280,
		RiskMsg:      "Kernel eBPF map/program loading and tracing",
	},
	{
		Name:         "ptrace",
		X86Syscall:   101,
		Arm64Syscall: 117,
		RiskMsg:      "Process memory inspection and register modification",
	},
	{
		Name:         "kexec_load",
		X86Syscall:   246,
		Arm64Syscall: 104,
		RiskMsg:      "Replacing running kernel image in RAM",
	},
	{
		Name:         "userfaultfd",
		X86Syscall:   323,
		Arm64Syscall: 282,
		RiskMsg:      "User-space page fault handling (frequently abused in kernel UAF exploits)",
	},
	{
		Name:         "keyctl",
		X86Syscall:   250,
		Arm64Syscall: 219,
		RiskMsg:      "Kernel keyring manipulation",
	},
	{
		Name:         "open_by_handle_at",
		X86Syscall:   304,
		Arm64Syscall: 265,
		RiskMsg:      "Opening files by raw handle (mount namespace escape vector)",
	},
	{
		Name:         "process_vm_writev",
		X86Syscall:   311,
		Arm64Syscall: 271,
		RiskMsg:      "Writing directly into target process memory space",
	},
	{
		Name:         "reboot",
		X86Syscall:   169,
		Arm64Syscall: 142,
		RiskMsg:      "System shutdown / kernel restart",
	},
	{
		Name:         "mount",
		X86Syscall:   165,
		Arm64Syscall: 40,
		RiskMsg:      "Filesystem hierarchy mount manipulation",
	},
	{
		Name:         "pivot_root",
		X86Syscall:   217,
		Arm64Syscall: 41,
		RiskMsg:      "Changing container root filesystem directory",
	},
	{
		Name:         "io_uring_setup",
		X86Syscall:   425,
		Arm64Syscall: 425,
		RiskMsg:      "Kernel io_uring asynchronous I/O ring creation (frequent exploit surface)",
	},
	{
		Name:         "init_module",
		X86Syscall:   175,
		Arm64Syscall: 105,
		RiskMsg:      "Loading kernel modules directly from memory",
	},
	{
		Name:         "finit_module",
		X86Syscall:   313,
		Arm64Syscall: 273,
		RiskMsg:      "Loading kernel modules from open file descriptors",
	},
	{
		Name:         "perf_event_open",
		X86Syscall:   298,
		Arm64Syscall: 241,
		RiskMsg:      "Performance monitoring subsystem access (kernel attack surface)",
	},
	{
		Name:         "chroot",
		X86Syscall:   161,
		Arm64Syscall: 51,
		RiskMsg:      "Changing process root directory boundary",
	},
	{
		Name:         "syslog",
		X86Syscall:   103,
		Arm64Syscall: 116,
		RiskMsg:      "Reading/clearing kernel ring log buffer (kmsg leak)",
	},
}

// AuditSeccomp evaluates Seccomp configuration, filters count, notifier listeners, and BPF policy
func AuditSeccomp(pid int, kv map[string]string, noNewPrivs bool) *SeccompAuditDetails {
	details := &SeccompAuditDetails{
		Mode:        0,
		ModeDesc:    "Disabled",
		FilterCount: 0,
	}

	// 1. Read Seccomp Mode & Filter Count from /proc/[pid]/status
	if seccompVal, ok := kv["Seccomp"]; ok {
		details.Mode, _ = strconv.Atoi(seccompVal)
	}

	switch details.Mode {
	case 0:
		details.ModeDesc = "Disabled"
		details.Risks = append(details.Risks, "Seccomp is disabled. The process can execute any Linux system call, increasing kernel attack surface.")
		details.Recommendations = append(details.Recommendations, "Enable a default Seccomp filter profile (e.g. Docker default profile or custom seccomp.json) to restrict unused system calls.")
		return details
	case 1:
		details.ModeDesc = "Enabled (Strict)"
		details.FilterCount = 1
		details.PolicyArchitecture = "Default-Deny (Strict whitelist)"
		details.ProfileFingerprint = "Strict Whitelist Profile (read/write/exit/sigreturn)"
		return details
	case 2:
		details.ModeDesc = "Enabled (Filter Mode)"
	}

	// Read Seccomp_filters from status KV (present in Linux 5.9+)
	if filterVal, ok := kv["Seccomp_filters"]; ok {
		details.FilterCount, _ = strconv.Atoi(filterVal)
	} else {
		details.FilterCount = 1 // Default fallback if mode is 2
	}

	if details.FilterCount > 1 {
		details.Risks = append(details.Risks, fmt.Sprintf("Process has %d stacked Seccomp filters active. Stacked filters increase kernel evaluation latency.", details.FilterCount))
	}

	// 2. Check for Seccomp User Notification Listener FD (SECCOMP_RET_USER_NOTIF)
	notifierFD, hasNotifier := findSeccompListenerFD(pid)
	if hasNotifier {
		details.HasUserNotifier = true
		details.NotifierFD = notifierFD
		details.Risks = append(details.Risks, fmt.Sprintf("Active Seccomp User Notification listener detected on FD %d. Syscalls are intercepted by an external supervisor.", notifierFD))
	}

	// 3. Co-enforcement check with NoNewPrivs
	if !noNewPrivs {
		details.Risks = append(details.Risks, "Seccomp filter is active, but NoNewPrivs is disabled. Unprivileged subprocesses could attempt privilege escalation or SUID bypass.")
		details.Recommendations = append(details.Recommendations, "Set 'NoNewPrivileges=true' to ensure child processes maintain Seccomp filter enforcement.")
	}

	// 4. Detailed BPF Filter Inspection via ptrace (if privileged)
	bpfProg, err := fetchSeccompFilter(pid, 0)
	if err == nil && len(bpfProg) > 0 {
		details.InspectedViaPtrace = true
		analyzeSeccompBPF(bpfProg, details)
	} else if err != nil {
		note := fmt.Sprintf("BPF disassembly skipped (%v)", err)
		errStr := strings.ToLower(err.Error())
		if strings.Contains(errStr, "permission denied") || strings.Contains(errStr, "operation not permitted") || strings.Contains(errStr, "eperm") || strings.Contains(errStr, "ptrace") {
			if isCurrentProcessInChildUserNS() {
				note += " [Unprivileged LXC/Container sandbox: Linux kernel requires host CAP_SYS_ADMIN in init_user_ns to inspect BPF filters]"
				details.Recommendations = append(details.Recommendations, "Inside LXC/containers, sysctl parameters are read-only. Run 'sudo sysctl kernel.yama.ptrace_scope=0' on the host system (e.g. Proxmox VE host), or run nspect directly on the host.")
			} else {
				note += " [Restricted by Linux YAMA ptrace_scope or UserNS capability boundary]"
				details.Recommendations = append(details.Recommendations, "To inspect Seccomp BPF filter bytecode on running processes, run nspect as host root ('sudo ./nspect --pid <PID>') or set 'sudo sysctl kernel.yama.ptrace_scope=0' on the host system.")
			}
		}
		details.InspectionNotes = note
	}

	// 5. Query Seccomp Filter Metadata Flags (PTRACE_SECCOMP_GET_METADATA)
	if flags, err := fetchSeccompMetadata(pid); err == nil && len(flags) > 0 {
		details.MetadataFlags = flags
		for _, f := range flags {
			if f == "SPEC_ALLOW" {
				details.Risks = append(details.Risks, "Seccomp filter has SECCOMP_FILTER_FLAG_SPEC_ALLOW set, disabling Speculative Store Bypass mitigations (Spectre v4).")
			}
		}
	}

	// 6. Scan Kernel Audit Logs for recent Seccomp Violations
	if count, logs := scanSeccompAuditLogs(pid); count > 0 {
		details.ViolationsDetected = count
		details.RecentViolations = logs
		details.Risks = append(details.Risks, fmt.Sprintf("Detected %d recent Seccomp syscall violation log(s) for this process in system audit log.", count))
	}

	return details
}

// findSeccompListenerFD scans /proc/[pid]/fd to locate seccomp user-notification listeners
func findSeccompListenerFD(pid int) (int, bool) {
	fdDir := util.ProcPath(pid, "fd")
	entries, err := os.ReadDir(fdDir)
	if err != nil {
		return -1, false
	}

	for _, entry := range entries {
		linkPath, err := os.Readlink(filepath.Join(fdDir, entry.Name()))
		if err != nil {
			continue
		}
		if strings.Contains(linkPath, "seccomp-listener") || strings.Contains(linkPath, "seccomp_listener") {
			fdNum, err := strconv.Atoi(entry.Name())
			if err == nil {
				return fdNum, true
			}
		}
	}
	return -1, false
}

// fetchSeccompFilter uses ptrace(PTRACE_SECCOMP_GET_FILTER) to safely extract BPF instructions
func fetchSeccompFilter(pid int, filterIndex int) ([]SockFilter, error) {
	// Attempt 1: Direct ptrace from current user namespace (preserves host CAP_SYS_ADMIN in init_user_ns)
	prog, err := doFetchSeccompFilter(pid, filterIndex, false)
	if err == nil {
		return prog, nil
	}

	// Attempt 2: If direct ptrace fails, attempt entering target user namespace via setns
	progNS, errNS := doFetchSeccompFilter(pid, filterIndex, true)
	if errNS == nil {
		return progNS, nil
	}

	return nil, err
}

func doFetchSeccompFilter(pid int, filterIndex int, enterUserNS bool) ([]SockFilter, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	if enterUserNS {
		userNSPath := util.ProcPath(pid, "ns", "user")
		if userNsFd, err := os.Open(userNSPath); err == nil {
			sysSetns := uintptr(308) // x86_64
			if runtime.GOARCH == "arm64" {
				sysSetns = uintptr(268)
			}
			_, _, _ = syscall.Syscall(sysSetns, userNsFd.Fd(), 0x10000000, 0)
			_ = userNsFd.Close()
		}
	}

	// Attach ptrace
	_, _, errNo := syscall.Syscall6(syscall.SYS_PTRACE, uintptr(ptraceAttach), uintptr(pid), 0, 0, 0, 0)
	if errNo != 0 {
		return nil, fmt.Errorf("ptrace attach failed: %v", errNo)
	}
	defer func() {
		_, _, _ = syscall.Syscall6(syscall.SYS_PTRACE, uintptr(ptraceDetach), uintptr(pid), 0, 0, 0, 0)
	}()

	// Wait for process stop
	var status syscall.WaitStatus
	_, err := syscall.Wait4(pid, &status, 0, nil)
	if err != nil {
		return nil, fmt.Errorf("wait4 failed: %w", err)
	}

	// Fetch instruction count
	r1, _, errNo := syscall.Syscall6(syscall.SYS_PTRACE, uintptr(ptraceSeccompGetFilter), uintptr(pid), uintptr(filterIndex), 0, 0, 0)
	if errNo != 0 {
		return nil, fmt.Errorf("ptrace get filter len failed: %v", errNo)
	}

	count := int(r1)
	if count <= 0 || count > 4096 {
		return nil, fmt.Errorf("invalid filter instruction count: %d", count)
	}

	// Allocate buffer and fetch instructions
	instructions := make([]SockFilter, count)
	_, _, errNo = syscall.Syscall6(syscall.SYS_PTRACE, uintptr(ptraceSeccompGetFilter), uintptr(pid), uintptr(filterIndex), uintptr(unsafe.Pointer(&instructions[0])), 0, 0)
	if errNo != 0 {
		return nil, fmt.Errorf("ptrace read filter data failed: %v", errNo)
	}

	return instructions, nil
}

// fetchSeccompMetadata queries Seccomp filter flags via PTRACE_SECCOMP_GET_METADATA
func fetchSeccompMetadata(pid int) ([]string, error) {
	flags, err := doFetchSeccompMetadata(pid, false)
	if err == nil {
		return flags, nil
	}
	return doFetchSeccompMetadata(pid, true)
}

func doFetchSeccompMetadata(pid int, enterUserNS bool) ([]string, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	if enterUserNS {
		userNSPath := util.ProcPath(pid, "ns", "user")
		if userNsFd, err := os.Open(userNSPath); err == nil {
			sysSetns := uintptr(308) // x86_64
			if runtime.GOARCH == "arm64" {
				sysSetns = uintptr(268)
			}
			_, _, _ = syscall.Syscall(sysSetns, userNsFd.Fd(), 0x10000000, 0)
			_ = userNsFd.Close()
		}
	}

	_, _, errNo := syscall.Syscall6(syscall.SYS_PTRACE, uintptr(ptraceAttach), uintptr(pid), 0, 0, 0, 0)
	if errNo != 0 {
		return nil, fmt.Errorf("ptrace attach failed: %v", errNo)
	}
	defer func() {
		_, _, _ = syscall.Syscall6(syscall.SYS_PTRACE, uintptr(ptraceDetach), uintptr(pid), 0, 0, 0, 0)
	}()

	var status syscall.WaitStatus
	_, err := syscall.Wait4(pid, &status, 0, nil)
	if err != nil {
		return nil, fmt.Errorf("wait4 failed: %w", err)
	}

	var meta struct {
		FilterOff uint64
		Flags     uint64
	}

	r1, _, errNo := syscall.Syscall6(syscall.SYS_PTRACE, uintptr(0x420d), uintptr(pid), unsafe.Sizeof(meta), uintptr(unsafe.Pointer(&meta)), 0, 0)
	if errNo != 0 || r1 != 0 {
		return nil, fmt.Errorf("ptrace get metadata failed: %v", errNo)
	}

	var flags []string
	if (meta.Flags & 1) != 0 {
		flags = append(flags, "TSYNC")
	}
	if (meta.Flags & 2) != 0 {
		flags = append(flags, "LOG")
	}
	if (meta.Flags & 4) != 0 {
		flags = append(flags, "SPEC_ALLOW")
	}
	if (meta.Flags & 8) != 0 {
		flags = append(flags, "NEW_LISTENER")
	}
	return flags, nil
}

// scanSeccompAuditLogs checks system audit logs for recent Seccomp violation events for the target PID
func scanSeccompAuditLogs(pid int) (int, []string) {
	procName, _ := util.GetProcessName(pid)
	auditLogPaths := []string{
		"/var/log/audit/audit.log",
		"/var/log/kern.log",
		"/var/log/syslog",
		"/var/log/messages",
	}

	pidStr := fmt.Sprintf("pid=%d", pid)
	commStr := ""
	if procName != "" {
		commStr = fmt.Sprintf("comm=%q", procName)
	}

	var matches []string
	for _, path := range auditLogPaths {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		lines := strings.Split(string(data), "\n")
		startIdx := 0
		if len(lines) > 500 {
			startIdx = len(lines) - 500
		}
		for _, line := range lines[startIdx:] {
			if strings.Contains(line, "SECCOMP") || strings.Contains(line, "seccomp") {
				if strings.Contains(line, pidStr) || (commStr != "" && strings.Contains(line, commStr)) {
					lineTrim := strings.TrimSpace(line)
					if lineTrim != "" {
						matches = append(matches, lineTrim)
					}
				}
			}
		}
		if len(matches) > 0 {
			break
		}
	}
	return len(matches), matches
}

// FormatSeccompAction converts raw Seccomp return action bits into human readable description
func FormatSeccompAction(ret uint32) string {
	action := ret & seccompRetActionFull
	switch action {
	case seccompRetAllow:
		return "SECCOMP_RET_ALLOW"
	case seccompRetKillProcess:
		return "SECCOMP_RET_KILL_PROCESS"
	case seccompRetKillThread:
		return "SECCOMP_RET_KILL_THREAD"
	case seccompRetTrap:
		return "SECCOMP_RET_TRAP"
	case seccompRetErrno:
		errnoVal := ret & 0x0000ffff
		switch errnoVal {
		case 1:
			return "SECCOMP_RET_ERRNO (EPERM)"
		case 13:
			return "SECCOMP_RET_ERRNO (EACCES)"
		case 38:
			return "SECCOMP_RET_ERRNO (ENOSYS)"
		default:
			if errnoVal > 0 {
				return fmt.Sprintf("SECCOMP_RET_ERRNO (%d)", errnoVal)
			}
			return "SECCOMP_RET_ERRNO"
		}
	case seccompRetUserNotif:
		return "SECCOMP_RET_USER_NOTIF"
	case seccompRetTrace:
		return "SECCOMP_RET_TRACE"
	case seccompRetLog:
		return "SECCOMP_RET_LOG"
	default:
		return fmt.Sprintf("0x%08x", ret)
	}
}

func classifyActionName(ret uint32) string {
	action := ret & seccompRetActionFull
	switch action {
	case seccompRetAllow:
		return "ALLOW"
	case seccompRetKillProcess:
		return "KILL_PROCESS"
	case seccompRetKillThread:
		return "KILL_THREAD"
	case seccompRetTrap:
		return "TRAP"
	case seccompRetErrno:
		return "ERRNO"
	case seccompRetUserNotif:
		return "USER_NOTIF"
	case seccompRetTrace:
		return "TRACE"
	case seccompRetLog:
		return "LOG"
	default:
		return "OTHER"
	}
}

func parseArchName(archConst uint32) string {
	switch archConst {
	case 0xc000003e:
		return "AUDIT_ARCH_X86_64"
	case 0x40000003:
		return "AUDIT_ARCH_I386"
	case 0xc00000b7:
		return "AUDIT_ARCH_AARCH64"
	case 0x40000028:
		return "AUDIT_ARCH_ARM"
	case 0xc00000b4:
		return "AUDIT_ARCH_RISCV64"
	case 0x80000016:
		return "AUDIT_ARCH_S390X"
	default:
		return fmt.Sprintf("0x%08x", archConst)
	}
}

// analyzeSeccompBPF parses BPF instructions to classify default policy, validate arch, and audit high-risk syscalls
func analyzeSeccompBPF(prog []SockFilter, details *SeccompAuditDetails) {
	if len(prog) == 0 {
		return
	}

	details.InstructionCount = len(prog)
	details.ActionCounts = make(map[string]int)

	// Determine architecture
	isArm64 := runtime.GOARCH == "arm64"

	// 1. Audit Architecture Validation Check (offset 4 in seccomp_data) & Argument Inspection (offset >= 16)
	hasArchCheck := false
	var validatedArch string

	for i, ins := range prog {
		// Collect return action statistics
		if (ins.Code & 0x07) == bpfRet {
			actName := classifyActionName(ins.K)
			details.ActionCounts[actName]++
		}

		// Check for load of arch field (seccomp_data offset 4)
		if ins.Code == (bpfLd | bpfW | bpfAbs) && ins.K == 4 {
			hasArchCheck = true
			if i+1 < len(prog) && prog[i+1].Code == (bpfJmp | bpfJeq | bpfK) {
				validatedArch = parseArchName(prog[i+1].K)
			}
		}

		// Check for load of args fields (seccomp_data offset >= 16)
		if ins.Code == (bpfLd | bpfW | bpfAbs) && ins.K >= 16 {
			details.HasArgInspection = true
			details.ArgInspectionCount++
		}
	}

	details.ArchValidated = hasArchCheck
	details.ValidatedArchName = validatedArch

	if !hasArchCheck {
		details.ArchBypassRisk = true
		details.Risks = append(details.Risks, "Seccomp BPF filter does not validate system architecture (AUDIT_ARCH). 32-bit ABI or x32 syscall execution could bypass 64-bit filter rules.")
		details.Recommendations = append(details.Recommendations, "Ensure Seccomp BPF filters validate system architecture (AUDIT_ARCH_X86_64 / AUDIT_ARCH_AARCH64) as the first filter instruction.")
	}

	// 2. Find the Default Return Action (prefer untargeted fallthrough RET instruction)
	jumpTargets := make(map[int]bool)
	for i, ins := range prog {
		if (ins.Code & 0x07) == bpfJmp {
			op := ins.Code & 0xf0
			if op == 0x00 { // JA
				jumpTargets[i+1+int(ins.K)] = true
			} else {
				if ins.Jt > 0 {
					jumpTargets[i+1+int(ins.Jt)] = true
				}
				if ins.Jf > 0 {
					jumpTargets[i+1+int(ins.Jf)] = true
				}
			}
		}
	}

	var defaultRet uint32
	foundDefault := false
	for i := len(prog) - 1; i >= 0; i-- {
		if (prog[i].Code & 0x07) == bpfRet {
			if !jumpTargets[i] {
				defaultRet = prog[i].K
				foundDefault = true
				break
			}
		}
	}
	if !foundDefault {
		for i := len(prog) - 1; i >= 0; i-- {
			if (prog[i].Code & 0x07) == bpfRet {
				defaultRet = prog[i].K
				break
			}
		}
	}

	details.DefaultReturnAction = FormatSeccompAction(defaultRet)
	defaultAction := defaultRet & seccompRetActionFull

	if defaultAction == seccompRetAllow {
		details.PolicyArchitecture = "Default-Allow (Blacklist)"
		details.Risks = append(details.Risks, "Seccomp filter uses a Default-Allow (blacklist) policy. New or unlisted kernel system calls are automatically permitted.")
		details.Recommendations = append(details.Recommendations, "Adopt a Default-Kill or Default-Errno (whitelist) Seccomp policy to minimize kernel attack surface.")
	} else {
		details.PolicyArchitecture = "Default-Deny (Whitelist)"
	}

	// 3. Analyze target high-risk syscalls
	var audited []SeccompSyscallCheck
	blockedCount := 0
	for _, target := range targetHighRiskSyscalls {
		sysNr := target.X86Syscall
		if isArm64 {
			sysNr = target.Arm64Syscall
		}

		isEvaluated, actionCode, actionDetails := checkSyscallInBPF(prog, sysNr, defaultRet)
		statusStr := "Allowed"
		if isEvaluated && actionCode != seccompRetAllow {
			statusStr = "Blocked/Filtered"
			blockedCount++
		} else if !isEvaluated && defaultAction != seccompRetAllow {
			statusStr = "Blocked (Default Deny)"
			blockedCount++
		}

		audited = append(audited, SeccompSyscallCheck{
			Name:          target.Name,
			Syscall:       sysNr,
			Status:        statusStr,
			ActionDetails: actionDetails,
			Risk:          target.RiskMsg,
		})
	}
	details.AuditedSyscalls = audited

	// 4. Profile Fingerprinting
	if details.PolicyArchitecture == "Default-Deny (Whitelist)" {
		if blockedCount >= 7 {
			details.ProfileFingerprint = "Hardened Container Profile (Docker / Podman Default)"
		} else {
			details.ProfileFingerprint = "Custom Whitelist Seccomp Profile"
		}
	} else if details.PolicyArchitecture == "Default-Allow (Blacklist)" {
		details.ProfileFingerprint = "Custom Permissive Blacklist Profile"
	}
}

// checkSyscallInBPF scans BPF filter for explicit jumps on syscall number
func checkSyscallInBPF(prog []SockFilter, sysNr int, defaultRet uint32) (bool, uint32, string) {
	for i, ins := range prog {
		if ins.Code == (bpfJmp | bpfJeq | bpfK) && int(ins.K) == sysNr {
			targetIdx := i + 1 + int(ins.Jt)
			actCode, actStr := resolveJumpAction(prog, targetIdx)
			if actStr != "" {
				return true, actCode, actStr
			}
			return true, 0, "Custom Filter Logic"
		}
	}
	defaultAction := defaultRet & seccompRetActionFull
	return false, defaultAction, fmt.Sprintf("Default Action (%s)", FormatSeccompAction(defaultRet))
}

func resolveJumpAction(prog []SockFilter, startIdx int) (uint32, string) {
	curr := startIdx
	for steps := 0; steps < 10 && curr < len(prog); steps++ {
		ins := prog[curr]
		if (ins.Code & 0x07) == bpfRet {
			return ins.K & seccompRetActionFull, FormatSeccompAction(ins.K)
		}
		if (ins.Code & 0x07) == bpfJmp {
			op := ins.Code & 0xf0
			if op == 0x00 { // JA
				curr += 1 + int(ins.K)
				continue
			}
			curr += 1 + int(ins.Jt)
			continue
		}
		curr++
	}
	return 0, "Custom Filter Logic"
}

func isCurrentProcessInChildUserNS() bool {
	data, err := os.ReadFile("/proc/self/uid_map")
	if err != nil {
		return false
	}
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) == 3 {
			if fields[0] == "0" && fields[1] != "0" {
				return true
			}
		}
	}
	return false
}
