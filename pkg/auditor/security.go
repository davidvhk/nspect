package auditor

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"nspect/pkg/util"
)

// SecurityAuditResult holds the process credentials and hardening details.
type SecurityAuditResult struct {
	UID               int      `json:"uid"`
	EUID              int      `json:"euid"`
	GID               int      `json:"gid"`
	EGID              int      `json:"egid"`
	SeccompMode       int      `json:"seccomp_mode"`       // 0=disabled, 1=strict, 2=filter
	NoNewPrivs        bool     `json:"no_new_privs"`       // true/false
	LSMProfile        string   `json:"lsm_profile"`        // apparmor, selinux, or unconfined
	UserNSMapped      bool     `json:"usern_ns_mapped"`    // true if user namespace is virtualized (rootless)
	SetgroupsStatus   string   `json:"setgroups_status"`   // allow or deny
	InitProcessName   string   `json:"init_process_name"`  // PID 1 name
	CgroupMemoryLimit string   `json:"cgroup_memory_limit"` // memory max or unlimited
	CgroupPidsLimit   string   `json:"cgroup_pids_limit"`   // pids max or unlimited
	Risks             []string `json:"risks"`
	Recommendations   []string `json:"recommendations"`
	Score             int      `json:"score"` // 0 to 100
}

// AuditSecurity checks process level sandboxing and credential settings.
func AuditSecurity(pid int) (*SecurityAuditResult, error) {
	statusPath := util.ProcPath(pid, "status")
	kv, err := util.ParseKeyValuePair(statusPath)
	if err != nil {
		return nil, fmt.Errorf("failed to parse process status: %w", err)
	}

	var risks []string
	var recs []string
	scoreReduction := 0

	// 1. UID/GID checks
	uidVal, hasUID := kv["Uid"]
	gidVal, hasGID := kv["Gid"]

	uid, euid := -1, -1
	gid, egid := -1, -1

	if hasUID {
		fields := strings.Fields(uidVal)
		if len(fields) >= 2 {
			uid, _ = strconv.Atoi(fields[0])
			euid, _ = strconv.Atoi(fields[1])
		}
	}
	if hasGID {
		fields := strings.Fields(gidVal)
		if len(fields) >= 2 {
			gid, _ = strconv.Atoi(fields[0])
			egid, _ = strconv.Atoi(fields[1])
		}
	}

	// 2. User Namespace mapping check (rootless status)
	isRootless := false
	maxMapRange := 0
	uidMapPath := util.ProcPath(pid, "uid_map")
	uidMapData, err := os.ReadFile(uidMapPath)
	if err == nil {
		lines := strings.Split(string(uidMapData), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) == 3 {
				containerUID := fields[0]
				hostUID := fields[1]
				lengthStr := fields[2]
				length, _ := strconv.Atoi(lengthStr)
				if length > maxMapRange {
					maxMapRange = length
				}

				// If UID 0 in container maps to host UID 0 (usually indicated by hostUID "0" and length "4294967295" or similar)
				if containerUID == "0" && hostUID != "0" {
					isRootless = true
				}
				
				// A common Docker/rootless setup maps UID 0 to a non-zero host UID
				// e.g. 0 100000 65536
			}
		}
	}

	if isRootless && maxMapRange > 1 {
		risks = append(risks, fmt.Sprintf("User namespace maps a large range of UIDs (%d). This exposes a larger identity translation surface.", maxMapRange))
		recs = append(recs, "For single-process sandboxes, restrict the user namespace mapping range to exactly 1 UID (e.g. '0 1000 1').")
	}

	if euid == 0 {
		if !isRootless {
			risks = append(risks, "Process is running as EUID 0 (root) on the host filesystem namespace. If a breakout occurs, the attacker has host root privileges.")
			recs = append(recs, "Configure the process or container to run as a non-root user (UID > 0), or enable user namespace mapping (rootless containers).")
			scoreReduction += 30
		} else {
			// EUID 0 but mapped (rootless)
			recs = append(recs, "Although process runs as root internally, it is mapped to a non-privileged user on the host. Maintain this user namespace isolation.")
			recs = append(recs, "Unprivileged container boundary detected. Ensure host-level LXC/container configuration enforces 'nodev=1,nosuid=1,noexec=1' on all host mount points to restrict raw device node creation.")
		}
	}

	// 3. Seccomp Audit
	seccompMode := 0
	seccompVal, hasSeccomp := kv["Seccomp"]
	if hasSeccomp {
		seccompMode, _ = strconv.Atoi(seccompVal)
	}

	switch seccompMode {
	case 0:
		risks = append(risks, "Seccomp is disabled. The process can execute any Linux system call, increasing kernel attack surface.")
		recs = append(recs, "Enable a default Seccomp filter profile (e.g. Docker default profile or custom seccomp.json) to restrict unused system calls.")
		scoreReduction += 20
	case 1:
		// Strict (very rare for containers, basically only read, write, exit, sigreturn)
	case 2:
		// Seccomp-BPF enabled (Standard Docker/Containerd default)
	}

	// 4. NoNewPrivs Audit
	noNewPrivs := false
	noNewPrivsVal, hasNoNewPrivs := kv["NoNewPrivs"]
	if hasNoNewPrivs {
		if strings.TrimSpace(noNewPrivsVal) == "1" {
			noNewPrivs = true
		}
	}

	if !noNewPrivs {
		risks = append(risks, "NoNewPrivs flag is not set. Subprocesses can gain new privileges via SUID binaries or file capabilities.")
		recs = append(recs, "Set 'NoNewPrivileges=true' in systemd or '--security-opt=no-new-privileges' in Docker to prevent privilege escalation.")
		scoreReduction += 15
	}

	// 5. LSM (Linux Security Module) Profile
	lsmProfile := "none"
	lsmPath := util.ProcPath(pid, "attr", "current")
	lsmData, err := os.ReadFile(lsmPath)
	if err == nil {
		profile := strings.TrimSpace(string(lsmData))
		if profile != "" {
			lsmProfile = profile
		}
	}

	if lsmProfile == "none" || lsmProfile == "unconfined" || strings.Contains(lsmProfile, "unconfined") {
		risks = append(risks, "AppArmor/SELinux profile is unconfined or disabled. The process lacks mandatory access controls (MAC).")
		recs = append(recs, "Apply a confined AppArmor profile (e.g. apparmor:docker-default) or enable SELinux to enforce runtime restrictions.")
		scoreReduction += 20
	}

	// 6. Setgroups check
	setgroupsStatus := GetSetgroupsStatus(pid)
	if setgroupsStatus == "allow" && isRootless {
		risks = append(risks, "The user namespace allows calling setgroups(2). This can allow dropping group memberships to bypass negative permissions.")
		recs = append(recs, "Disable group capability changes by setting '/proc/[pid]/setgroups' to 'deny' inside the user namespace configuration.")
		scoreReduction += 10
	}

	// 7. PID 1 Check
	initProcName, _ := FindPID1Name(pid)
	isPidIsolated := false
	targetPidNS, err := GetNamespaceInode(pid, "pid")
	if err == nil {
		hostPidNS, err := GetNamespaceInode(1, "pid")
		if err != nil {
			hostPidNS, _ = GetNamespaceInode(os.Getpid(), "pid")
		}
		if hostPidNS != 0 && targetPidNS != hostPidNS {
			isPidIsolated = true
		}
	}
	if isPidIsolated && initProcName != "" && initProcName != "unknown" {
		standardInits := map[string]bool{
			"systemd": true, "init": true, "tini": true, "dumb-init": true, "s6-svscan": true, "runit": true, "pause": true,
		}
		if !standardInits[initProcName] {
			risks = append(risks, fmt.Sprintf("PID 1 in isolated process namespace is a non-standard init process (%s). This might lead to zombie process accumulation.", initProcName))
			recs = append(recs, "Use a lightweight init system like tini or dumb-init as the container/sandbox entrypoint to reap zombie processes.")
			scoreReduction += 10
		}
	}

	// 8. Cgroup Limits check
	memLimit, pidsLimit := GetCgroupLimits(pid)
	isIsolated := false
	targetMntNS, err := GetNamespaceInode(pid, "mnt")
	if err == nil {
		hostMntNS, err := GetNamespaceInode(1, "mnt")
		if err != nil {
			hostMntNS, _ = GetNamespaceInode(os.Getpid(), "mnt")
		}
		if hostMntNS != 0 && targetMntNS != hostMntNS {
			isIsolated = true
		}
	}
	if isIsolated {
		if memLimit == "unlimited" || memLimit == "unknown" {
			risks = append(risks, "No cgroup memory limit is enforced. A memory leak or crash loop could cause host memory exhaustion.")
			recs = append(recs, "Enforce a cgroup memory limit (e.g. via Docker's '--memory' option or systemd's 'MemoryMax' setting).")
			scoreReduction += 10
		}
		if pidsLimit == "unlimited" || pidsLimit == "unknown" {
			risks = append(risks, "No cgroup process/thread limit is enforced. The namespace could exhaust host PIDs via a fork bomb.")
			recs = append(recs, "Enforce a cgroup PIDs limit (e.g. via Docker's '--pids-limit' or systemd's 'TasksMax' setting).")
			scoreReduction += 10
		}
	}

	// 9. CPU SMT and Core Scheduling advisory
	smtActive := false
	if smtData, err := os.ReadFile("/sys/devices/system/cpu/smt/active"); err == nil {
		if strings.TrimSpace(string(smtData)) == "1" {
			smtActive = true
		}
	} else if smtControl, err := os.ReadFile("/sys/devices/system/cpu/smt/control"); err == nil {
		if strings.TrimSpace(string(smtControl)) == "on" {
			smtActive = true
		}
	}
	if smtActive {
		risks = append(risks, "CPU SMT (Hyper-Threading) is active on the host. In multi-tenant environments, ensure CPU Core Scheduling (PR_SCHED_CORE) is enforced by the orchestrator to mitigate side-channel leaks (e.g. Spectre, MDS).")
	}

	// 10. GID Map Privilege checks
	checkGIDMapPrivilege(pid, &risks, &recs, &scoreReduction)

	// 11. Kernel Helper Writability checks
	checkKernelHelperWritability(pid, &risks, &recs, &scoreReduction)

	finalScore := 100 - scoreReduction
	if finalScore < 0 {
		finalScore = 0
	}

	return &SecurityAuditResult{
		UID:               uid,
		EUID:              euid,
		GID:               gid,
		EGID:              egid,
		SeccompMode:       seccompMode,
		NoNewPrivs:        noNewPrivs,
		LSMProfile:        lsmProfile,
		UserNSMapped:      isRootless,
		SetgroupsStatus:   setgroupsStatus,
		InitProcessName:   initProcName,
		CgroupMemoryLimit: memLimit,
		CgroupPidsLimit:   pidsLimit,
		Risks:             risks,
		Recommendations:   recs,
		Score:             finalScore,
	}, nil
}

// GetSetgroupsStatus retrieves the setgroups permission status for the process.
func GetSetgroupsStatus(pid int) string {
	setgroupsPath := util.ProcPath(pid, "setgroups")
	data, err := os.ReadFile(setgroupsPath)
	if err != nil {
		return "unsupported"
	}
	return strings.TrimSpace(string(data))
}

// FindPID1Name scans /proc to find the process name running as PID 1 inside the target's PID namespace.
func FindPID1Name(targetPID int) (string, error) {
	targetNS, err := GetNamespaceInode(targetPID, "pid")
	if err != nil {
		return "", err
	}

	hostPidNS, err := GetNamespaceInode(1, "pid")
	if err != nil {
		hostPidNS, _ = GetNamespaceInode(os.Getpid(), "pid")
	}

	// If sharing host PID namespace, PID 1 is the system init.
	if hostPidNS != 0 && targetNS == hostPidNS {
		name, err := util.GetProcessName(1)
		if err != nil {
			return "systemd", nil
		}
		return name, nil
	}

	entries, err := os.ReadDir("/proc")
	if err != nil {
		return "", err
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 1 {
			continue
		}
		ns, err := GetNamespaceInode(pid, "pid")
		if err != nil || ns != targetNS {
			continue
		}
		statusPath := util.ProcPath(pid, "status")
		kv, err := util.ParseKeyValuePair(statusPath)
		if err == nil {
			nspidVal, hasNSpid := kv["NSpid"]
			if hasNSpid {
				fields := strings.Fields(nspidVal)
				if len(fields) > 0 {
					lastPID := fields[len(fields)-1]
					if lastPID == "1" {
						name, err := util.GetProcessName(pid)
						if err == nil {
							return name, nil
						}
					}
				}
			}
		}
	}
	return "unknown", fmt.Errorf("could not find PID 1 in namespace")
}

// GetCgroupLimits resolves cgroup resource limits for memory and PIDs.
func GetCgroupLimits(pid int) (string, string) {
	cgroupPath := util.ProcPath(pid, "cgroup")
	data, err := os.ReadFile(cgroupPath)
	if err != nil {
		return "unknown", "unknown"
	}

	var cgPath string
	isV2 := false
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Cgroup v2 is "0::/path"
		if strings.HasPrefix(line, "0::") {
			cgPath = line[3:]
			isV2 = true
			break
		}
		// Cgroup v1 fallback for memory controller
		parts := strings.Split(line, ":")
		if len(parts) == 3 && strings.Contains(parts[1], "memory") {
			cgPath = parts[2]
		}
	}

	if cgPath == "" || cgPath == "/" {
		return "unlimited", "unlimited"
	}

	memLimit := "unlimited"
	pidsLimit := "unlimited"

	if isV2 {
		memFile := fmt.Sprintf("/sys/fs/cgroup%s/memory.max", cgPath)
		if mData, err := os.ReadFile(memFile); err == nil {
			val := strings.TrimSpace(string(mData))
			if val == "max" {
				memLimit = "unlimited"
			} else {
				memLimit = val
			}
		} else if os.IsPermission(err) {
			memLimit = "restricted"
		} else {
			memLimit = "unknown"
		}

		pidsFile := fmt.Sprintf("/sys/fs/cgroup%s/pids.max", cgPath)
		if pData, err := os.ReadFile(pidsFile); err == nil {
			val := strings.TrimSpace(string(pData))
			if val == "max" {
				pidsLimit = "unlimited"
			} else {
				pidsLimit = val
			}
		} else if os.IsPermission(err) {
			pidsLimit = "restricted"
		} else {
			pidsLimit = "unknown"
		}
	} else {
		memFile := fmt.Sprintf("/sys/fs/cgroup/memory%s/memory.limit_in_bytes", cgPath)
		if mData, err := os.ReadFile(memFile); err == nil {
			val := strings.TrimSpace(string(mData))
			if val != "" && !strings.HasPrefix(val, "922337203") {
				memLimit = val
			}
		} else if os.IsPermission(err) {
			memLimit = "restricted"
		} else {
			memLimit = "unknown"
		}

		pidsFile := fmt.Sprintf("/sys/fs/cgroup/pids%s/pids.max", cgPath)
		if pData, err := os.ReadFile(pidsFile); err == nil {
			val := strings.TrimSpace(string(pData))
			if val == "max" {
				pidsLimit = "unlimited"
			} else if val != "" {
				pidsLimit = val
			}
		} else if os.IsPermission(err) {
			pidsLimit = "restricted"
		} else {
			pidsLimit = "unknown"
		}
	}

	return memLimit, pidsLimit
}

// getSensitiveGIDs parses host /etc/group to retrieve GIDs for sensitive administrative groups.
func getSensitiveGIDs() map[int]string {
	sensitiveNames := map[string]bool{
		"docker": true, "sudo": true, "wheel": true, "disk": true, "lxd": true, "libvirt": true, "shadow": true, "adm": true,
	}
	result := make(map[int]string)
	
	// Read /etc/group
	data, err := os.ReadFile("/etc/group")
	if err != nil {
		// Fallback to default GIDs if we can't read it
		defaults := map[int]string{
			0: "root", 6: "disk", 27: "sudo", 42: "shadow", 999: "docker", 998: "docker",
		}
		return defaults
	}
	
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) >= 3 {
			name := parts[0]
			gidStr := parts[2]
			if sensitiveNames[name] || name == "root" {
				if gid, err := strconv.Atoi(gidStr); err == nil {
					result[gid] = name
				}
			}
		}
	}
	return result
}

// checkGIDMapPrivilege parses GID mappings inside the user namespace to ensure no sensitive host groups are mapped.
func checkGIDMapPrivilege(pid int, risks *[]string, recs *[]string, scoreReduction *int) {
	gidMapPath := util.ProcPath(pid, "gid_map")
	data, err := os.ReadFile(gidMapPath)
	if err != nil {
		return
	}
	
	sensitiveGIDs := getSensitiveGIDs()
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 3 {
			containerGID, _ := strconv.Atoi(fields[0])
			hostGID, _ := strconv.Atoi(fields[1])
			length, _ := strconv.Atoi(fields[2])
			
			// Check if any mapped host GID falls into sensitive GIDs
			for gidVal, groupName := range sensitiveGIDs {
				if hostGID <= gidVal && gidVal < hostGID+length {
					// Skip container GID 0 mapping to host GID 0 as it is standard and handled by user ns mapping flags
					if gidVal == 0 && containerGID == 0 {
						continue
					}
					*risks = append(*risks, fmt.Sprintf("User namespace GID map exposes host group '%s' (GID %d) inside the container (mapped to container GID %d).", groupName, gidVal, containerGID+(gidVal-hostGID)))
					*recs = append(*recs, fmt.Sprintf("Avoid mapping sensitive host GID %d (%s) into the container's user namespace.", gidVal, groupName))
					*scoreReduction += 15
				}
			}
		}
	}
}

// checkKernelHelperWritability evaluates if core_pattern or uevent_helper are writable inside the container.
func checkKernelHelperWritability(pid int, risks *[]string, recs *[]string, scoreReduction *int) {
	helpers := []string{
		"/proc/sys/kernel/core_pattern",
		"/sys/kernel/uevent_helper",
	}
	
	for _, h := range helpers {
		// Construct the path from the host's perspective via /proc/[pid]/root/
		targetPath := filepath.Join(util.ProcPath(pid, "root"), h)
		
		// Attempt to open the file for writing (as host-root, this checks if the mount is rw in the target namespace)
		f, err := os.OpenFile(targetPath, os.O_WRONLY, 0)
		if err == nil {
			f.Close()
			*risks = append(*risks, fmt.Sprintf("Writable kernel helper path detected: %s. An attacker can write to this file to execute arbitrary commands on the host when a crash or kernel event occurs.", h))
			*recs = append(*recs, fmt.Sprintf("Mount the parent path of '%s' as read-only (e.g. read-only /proc or mask /proc/sys) inside the container.", h))
			*scoreReduction += 25
		}
	}
}
