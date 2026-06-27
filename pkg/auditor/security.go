package auditor

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"nspect/pkg/util"
)

// SecurityAuditResult holds the process credentials and hardening details.
type SecurityAuditResult struct {
	UID              int      `json:"uid"`
	EUID             int      `json:"euid"`
	GID              int      `json:"gid"`
	EGID             int      `json:"egid"`
	SeccompMode      int      `json:"seccomp_mode"`       // 0=disabled, 1=strict, 2=filter
	NoNewPrivs       bool     `json:"no_new_privs"`       // true/false
	LSMProfile       string   `json:"lsm_profile"`        // apparmor, selinux, or unconfined
	UserNSMapped     bool     `json:"usern_ns_mapped"`    // true if user namespace is virtualized (rootless)
	Risks            []string `json:"risks"`
	Recommendations  []string `json:"recommendations"`
	Score            int      `json:"score"` // 0 to 100
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

				// If UID 0 in container maps to host UID 0 (usually indicated by hostUID "0" and length "4294967295" or similar)
				if containerUID == "0" && hostUID != "0" {
					isRootless = true
				}
				
				// A common Docker/rootless setup maps UID 0 to a non-zero host UID
				// e.g. 0 100000 65536
			}
		}
	}

	if euid == 0 {
		if !isRootless {
			risks = append(risks, "Process is running as EUID 0 (root) on the host filesystem namespace. If a breakout occurs, the attacker has host root privileges.")
			recs = append(recs, "Configure the process or container to run as a non-root user (UID > 0), or enable user namespace mapping (rootless containers).")
			scoreReduction += 30
		} else {
			// EUID 0 but mapped (rootless)
			recs = append(recs, "Although process runs as root internally, it is mapped to a non-privileged user on the host. Maintain this user namespace isolation.")
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

	finalScore := 100 - scoreReduction
	if finalScore < 0 {
		finalScore = 0
	}

	return &SecurityAuditResult{
		UID:             uid,
		EUID:            euid,
		GID:             gid,
		EGID:            egid,
		SeccompMode:     seccompMode,
		NoNewPrivs:      noNewPrivs,
		LSMProfile:      lsmProfile,
		UserNSMapped:    isRootless,
		Risks:           risks,
		Recommendations: recs,
		Score:           finalScore,
	}, nil
}
