package auditor

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// AuditReport aggregates all findings for a process.
type AuditReport struct {
	PID          int                   `json:"pid"`
	ProcessName  string                `json:"process_name"`
	Cmdline      string                `json:"cmdline"`
	Namespaces   *NamespaceAuditResult `json:"namespaces"`
	Capabilities *CapabilityAuditResult `json:"capabilities"`
	Mounts       *MountAuditResult     `json:"mounts"`
	Security     *SecurityAuditResult  `json:"security"`
	Env          *EnvAuditResult       `json:"environment"`
	Network      *NetAuditResult       `json:"network"`
	FD           *FDAuditResult        `json:"file_descriptors"`
	Filesystem   *FilesystemAuditResult `json:"filesystem"`
	Systemd      *SystemdAuditResult   `json:"systemd,omitempty"`
	ProcessTree  *ProcessTreeAuditResult `json:"process_tree,omitempty"`
	Kernel       *KernelAuditResult    `json:"kernel,omitempty"`
	Remediations *RemediationArtifacts `json:"remediations,omitempty"`
	CVEs         []CVEFinding          `json:"cves,omitempty"`
	OverallScore int                   `json:"overall_score"`
}

// GenerateReport runs all audits on the target PID.
func GenerateReport(pid int, name, cmdline string, maskSecrets bool) (*AuditReport, error) {
	nsResult, err := AuditNamespaces(pid)
	if err != nil {
		return nil, fmt.Errorf("failed auditing namespaces: %w", err)
	}

	capResult, err := AuditCapabilities(pid)
	if err != nil {
		return nil, fmt.Errorf("failed auditing capabilities: %w", err)
	}

	mountResult, err := AuditMounts(pid)
	if err != nil {
		return nil, fmt.Errorf("failed auditing mounts: %w", err)
	}

	secResult, err := AuditSecurity(pid)
	if err != nil {
		return nil, fmt.Errorf("failed auditing security: %w", err)
	}

	envResult, err := AuditEnv(pid, maskSecrets)
	if err != nil {
		envResult = &EnvAuditResult{Score: 100}
	}

	netResult, err := AuditNetwork(pid)
	if err != nil {
		netResult = &NetAuditResult{}
	}

	fdResult, err := AuditFD(pid)
	if err != nil {
		fdResult = &FDAuditResult{Score: 100}
	}

	fsResult, err := AuditFilesystem(pid)
	if err != nil {
		fsResult = &FilesystemAuditResult{Score: 100}
	}

	sysdResult, err := AuditSystemd(pid, name)
	if err != nil {
		sysdResult = nil
	}

	treeResult, err := AuditProcessTree(pid)
	if err != nil {
		treeResult = nil
	}

	// Calculate overall score (weighted average)
	overall := (nsResult.Score*20 + capResult.Score*20 + mountResult.Score*15 + secResult.Score*15 + envResult.Score*10 + fsResult.Score*10 + fdResult.Score*10) / 100
	if sysdResult != nil {
		overall = (nsResult.Score*18 + capResult.Score*18 + mountResult.Score*14 + secResult.Score*14 + envResult.Score*10 + fsResult.Score*10 + fdResult.Score*8 + sysdResult.Score*8) / 100
	}

	report := &AuditReport{
		PID:          pid,
		ProcessName:  name,
		Cmdline:      cmdline,
		Namespaces:   nsResult,
		Capabilities: capResult,
		Mounts:       mountResult,
		Security:     secResult,
		Env:          envResult,
		Network:      netResult,
		FD:           fdResult,
		Filesystem:   fsResult,
		Systemd:      sysdResult,
		ProcessTree:  treeResult,
		OverallScore: overall,
	}

	report.Remediations = GenerateRemediations(report)
	report.CVEs = EvaluateCVEs(report)

	return report, nil
}

// RenderJSON formats the report in JSON.
func (r *AuditReport) RenderJSON() (string, error) {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// Color formatting definitions
const (
	Reset     = "\033[0m"
	Bold      = "\033[1m"
	Red       = "\033[31m"
	Green     = "\033[32m"
	Yellow    = "\033[33m"
	Blue      = "\033[34m"
	Cyan      = "\033[36m"
	Gray      = "\033[90m"
	BgRed     = "\033[41m"
	BgGreen   = "\033[42m"
	BgYellow  = "\033[43m"
)

// RenderCLI generates a beautifully formatted console output.
func (r *AuditReport) RenderCLI() string {
	var sb strings.Builder

	// Header
	sb.WriteString(fmt.Sprintf("\n%s%s=== LINUX CONTAINER & SANDBOX AUDIT REPORT ===%s\n", Bold, Cyan, Reset))
	sb.WriteString(fmt.Sprintf("%sTarget Process:%s %s (PID: %d)\n", Bold, Reset, r.ProcessName, r.PID))
	if r.Cmdline != "" {
		sb.WriteString(fmt.Sprintf("%sCommand Line:%s  %s\n", Bold, Reset, r.Cmdline))
	}

	// Score Badge
	scoreColor := Green
	if r.OverallScore < 50 {
		scoreColor = Red
	} else if r.OverallScore < 80 {
		scoreColor = Yellow
	}
	sb.WriteString(fmt.Sprintf("%sSecurity Score:%s %s%d/100%s\n", Bold, Reset, scoreColor+Bold, r.OverallScore, Reset))
	sb.WriteString(strings.Repeat("-", 60) + "\n\n")

	// 1. Namespace Isolation
	sb.WriteString(fmt.Sprintf("%s[1] NAMESPACE ISOLATION%s (Score: %d/100)\n", Bold+Underline, Reset, r.Namespaces.Score))
	for _, ns := range r.Namespaces.Namespaces {
		status := fmt.Sprintf("%sISOLATED%s", Green, Reset)
		if ns.IsSharedWithHost {
			status = fmt.Sprintf("%s%sSHARED WITH HOST%s", Bold, Red, Reset)
		}
		sb.WriteString(fmt.Sprintf("  - %-8s : %s (Target Inode: %d)\n", ns.Name, status, ns.TargetInode))
		if ns.IsSharedWithHost {
			sb.WriteString(fmt.Sprintf("    %sRisk: %s%s\n", Yellow, ns.Description, Reset))
		}
	}
	sb.WriteString("\n")

	// 2. Security Context & LSM
	sb.WriteString(fmt.Sprintf("%s[2] PROCESS SECURITY CONTEXT%s (Score: %d/100)\n", Bold+Underline, Reset, r.Security.Score))
	uidStatus := fmt.Sprintf("UID=%d, EUID=%d", r.Security.UID, r.Security.EUID)
	if r.Security.EUID == 0 {
		if r.Security.UserNSMapped {
			uidStatus += fmt.Sprintf(" (%sRootless/Mapped%s)", Green, Reset)
		} else {
			uidStatus += fmt.Sprintf(" (%s%sRoot/Host Namespace%s)", Bold, Red, Reset)
		}
	}
	sb.WriteString(fmt.Sprintf("  - User Context : %s\n", uidStatus))

	seccompDesc := "Disabled"
	seccompColor := Red
	if r.Security.SeccompMode == 2 {
		seccompDesc = "Enabled (Filter)"
		seccompColor = Green
		if r.Security.SeccompDetails != nil && r.Security.SeccompDetails.PolicyArchitecture != "" {
			seccompDesc = fmt.Sprintf("Enabled (Filter - %s)", r.Security.SeccompDetails.PolicyArchitecture)
		}
	} else if r.Security.SeccompMode == 1 {
		seccompDesc = "Enabled (Strict)"
		seccompColor = Green
	}
	sb.WriteString(fmt.Sprintf("  - Seccomp      : %s%s%s\n", seccompColor, seccompDesc, Reset))
	if r.Security.SeccompMode == 2 {
		filterCountStr := "1 active filter"
		if r.Security.SeccompFilters > 1 {
			filterCountStr = fmt.Sprintf("%d stacked filters", r.Security.SeccompFilters)
		}
		sb.WriteString(fmt.Sprintf("  - Seccomp Filters: %s\n", filterCountStr))
	}
	if r.Security.SeccompDetails != nil {
		sd := r.Security.SeccompDetails
		if sd.ProfileFingerprint != "" {
			sb.WriteString(fmt.Sprintf("  - Seccomp Profile: %s%s%s\n", Cyan, sd.ProfileFingerprint, Reset))
		}
		if sd.InstructionCount > 0 {
			sb.WriteString(fmt.Sprintf("  - BPF Filter Len : %d instructions\n", sd.InstructionCount))
		}
		if sd.DefaultReturnAction != "" {
			defaultColor := Red
			if strings.Contains(sd.DefaultReturnAction, "KILL") || strings.Contains(sd.DefaultReturnAction, "ERRNO") || strings.Contains(sd.DefaultReturnAction, "TRAP") {
				defaultColor = Green
			}
			sb.WriteString(fmt.Sprintf("  - Default Action : %s%s%s\n", defaultColor, sd.DefaultReturnAction, Reset))
		}
		if len(sd.ActionCounts) > 0 {
			var actionStrs []string
			for act, cnt := range sd.ActionCounts {
				actionStrs = append(actionStrs, fmt.Sprintf("%s: %d", act, cnt))
			}
			sort.Strings(actionStrs)
			sb.WriteString(fmt.Sprintf("  - BPF Actions    : %s\n", strings.Join(actionStrs, ", ")))
		}
		if sd.HasArgInspection {
			sb.WriteString(fmt.Sprintf("  - Arg Filtering  : %sActive (%d argument checks)%s\n", Green, sd.ArgInspectionCount, Reset))
		}
		if len(sd.MetadataFlags) > 0 {
			sb.WriteString(fmt.Sprintf("  - Seccomp Flags  : %s\n", strings.Join(sd.MetadataFlags, ", ")))
		}
		if sd.InspectedViaPtrace {
			archStatus := fmt.Sprintf("%sValidated (AUDIT_ARCH check present)%s", Green, Reset)
			if sd.ValidatedArchName != "" {
				archStatus = fmt.Sprintf("%sValidated (%s)%s", Green, sd.ValidatedArchName, Reset)
			}
			if !sd.ArchValidated {
				archStatus = fmt.Sprintf("%sUnvalidated (32-bit / ABI bypass risk)%s", Red, Reset)
			}
			sb.WriteString(fmt.Sprintf("  - Multi-Arch Check: %s\n", archStatus))
		}
		if sd.ViolationsDetected > 0 {
			sb.WriteString(fmt.Sprintf("  - Seccomp Violations: %s%d event(s) logged%s\n", Red, sd.ViolationsDetected, Reset))
		}
	}
	if r.Security.HasSeccompListener && r.Security.SeccompDetails != nil {
		sb.WriteString(fmt.Sprintf("  - Seccomp Notifier: Active (FD %d)\n", r.Security.SeccompDetails.NotifierFD))
	}
	if r.Security.SeccompDetails != nil && r.Security.SeccompDetails.InspectionNotes != "" && !r.Security.SeccompDetails.InspectedViaPtrace {
		sb.WriteString(fmt.Sprintf("  - BPF Filter Audit: %s%s%s\n", Yellow, r.Security.SeccompDetails.InspectionNotes, Reset))
		noteLower := strings.ToLower(r.Security.SeccompDetails.InspectionNotes)
		if strings.Contains(noteLower, "permission denied") || strings.Contains(noteLower, "operation not permitted") || strings.Contains(noteLower, "eperm") || strings.Contains(noteLower, "ptrace") {
			if strings.Contains(r.Security.SeccompDetails.InspectionNotes, "Unprivileged LXC/Container") {
				sb.WriteString(fmt.Sprintf("    %sTip: Running in LXC/container. Execute 'sudo sysctl kernel.yama.ptrace_scope=0' on the HOST machine (e.g. Proxmox VE host), or run nspect on the host targeting PID %d.%s\n", Gray, r.PID, Reset))
			} else {
				sb.WriteString(fmt.Sprintf("    %sTip: Run 'sudo ./nspect --pid %d' (for CAP_SYS_PTRACE), or run 'sudo sysctl kernel.yama.ptrace_scope=0' on the host system.%s\n", Gray, r.PID, Reset))
			}
		}
	}
	if r.Security.SeccompDetails != nil && len(r.Security.SeccompDetails.AuditedSyscalls) > 0 {
		sb.WriteString(fmt.Sprintf("    %sAudited High-Risk Syscalls:%s\n", Gray, Reset))
		for _, sc := range r.Security.SeccompDetails.AuditedSyscalls {
			scColor := Green
			if sc.Status == "Allowed" {
				scColor = Yellow
			}
			actStr := sc.ActionDetails
			if actStr == "" {
				actStr = sc.Status
			}
			sb.WriteString(fmt.Sprintf("      - %-18s (nr %3d): %s%-22s%s [%s] | %s\n", sc.Name, sc.Syscall, scColor, sc.Status, Reset, actStr, sc.Risk))
		}
	}

	nnpStatus := fmt.Sprintf("%sNo%s", Red, Reset)
	if r.Security.NoNewPrivs {
		nnpStatus = fmt.Sprintf("%sYes%s", Green, Reset)
	}
	sb.WriteString(fmt.Sprintf("  - NoNewPrivs   : %s\n", nnpStatus))
	sb.WriteString(fmt.Sprintf("  - LSM Status   : %s\n", r.Security.LSMProfile))
	if r.Security.SetgroupsStatus != "" {
		sgColor := Green
		if r.Security.SetgroupsStatus == "allow" && r.Security.UserNSMapped {
			sgColor = Yellow
		}
		sb.WriteString(fmt.Sprintf("  - Setgroups    : %s%s%s\n", sgColor, r.Security.SetgroupsStatus, Reset))
	}
	if r.Security.InitProcessName != "" {
		initColor := Green
		isPidIsolated := false
		if r.Namespaces != nil {
			for _, ns := range r.Namespaces.Namespaces {
				if ns.Name == "pid" && !ns.IsSharedWithHost {
					isPidIsolated = true
					break
				}
			}
		}
		if isPidIsolated {
			standardInits := map[string]bool{
				"systemd": true, "init": true, "tini": true, "dumb-init": true, "s6-svscan": true, "runit": true, "pause": true,
			}
			if !standardInits[r.Security.InitProcessName] {
				initColor = Yellow
			}
		}
		sb.WriteString(fmt.Sprintf("  - PID 1 Name   : %s%s%s\n", initColor, r.Security.InitProcessName, Reset))
	}
	if r.Security.CgroupMemoryLimit != "" && r.Security.CgroupMemoryLimit != "none" {
		memColor := Green
		if r.Security.CgroupMemoryLimit == "unlimited" || r.Security.CgroupMemoryLimit == "unknown" {
			memColor = Yellow
		}
		sb.WriteString(fmt.Sprintf("  - Cgroup Memory: %s%s%s\n", memColor, r.Security.CgroupMemoryLimit, Reset))
	}
	if r.Security.CgroupPidsLimit != "" && r.Security.CgroupPidsLimit != "none" {
		pidsColor := Green
		if r.Security.CgroupPidsLimit == "unlimited" || r.Security.CgroupPidsLimit == "unknown" {
			pidsColor = Yellow
		}
		sb.WriteString(fmt.Sprintf("  - Cgroup PIDs  : %s%s%s\n", pidsColor, r.Security.CgroupPidsLimit, Reset))
	}

	if len(r.Security.Risks) > 0 {
		sb.WriteString(fmt.Sprintf("  %s%sHardening Issues Identified:%s\n", Bold, Yellow, Reset))
		for _, risk := range r.Security.Risks {
			sb.WriteString(fmt.Sprintf("    * %s\n", risk))
		}
	}
	sb.WriteString("\n")

	// 3. Linux Capabilities
	sb.WriteString(fmt.Sprintf("%s[3] LINUX CAPABILITIES%s (Score: %d/100)\n", Bold+Underline, Reset, r.Capabilities.Score))
	if len(r.Capabilities.Sets.Effective) == 0 {
		sb.WriteString("  - Effective Capabilities: [None / Dropped]\n")
	} else {
		// Cap list truncation if too long
		capsShow := r.Capabilities.Sets.Effective
		if len(capsShow) > 10 {
			capsShow = append(capsShow[:10], fmt.Sprintf("... (%d total)", len(r.Capabilities.Sets.Effective)))
		}
		sb.WriteString(fmt.Sprintf("  - Effective Caps: %s\n", strings.Join(capsShow, ", ")))
	}

	if len(r.Capabilities.HighRiskCaps) > 0 {
		sb.WriteString(fmt.Sprintf("  %s%sSensitive Capabilities Found:%s\n", Bold, Red, Reset))
		for _, rc := range r.Capabilities.HighRiskCaps {
			color := Red
			if rc.RiskLevel == "Medium" {
				color = Yellow
			}
			sb.WriteString(fmt.Sprintf("    * %s%s%s (%s): %s\n", Bold, color, rc.Name, rc.RiskLevel, Reset+rc.Description))
		}
	} else {
		sb.WriteString("  - No critical capabilities found in active set.\n")
	}
	sb.WriteString("\n")

	// 4. Mount Table & Volume Exposure
	sb.WriteString(fmt.Sprintf("%s[4] MOUNT & VOLUME EXPOSURE%s (Score: %d/100)\n", Bold+Underline, Reset, r.Mounts.Score))
	sb.WriteString(fmt.Sprintf("  - Total Mount Points Evaluated: %d\n", len(r.Mounts.Mounts)))
	if len(r.Mounts.Risks) > 0 {
		sb.WriteString(fmt.Sprintf("  %s%sMount Exposures Discovered:%s\n", Bold, Red, Reset))
		for _, mr := range r.Mounts.Risks {
			color := Red
			if mr.RiskLevel == "High" {
				color = Red + Bold
			} else if mr.RiskLevel == "Medium" {
				color = Yellow
			} else if mr.RiskLevel == "Low" {
				color = Gray
			}
			sb.WriteString(fmt.Sprintf("    * %s%s %s%s -> Mounted at %s (%s)\n", color, mr.RiskLevel, Reset, mr.MountSource, mr.MountPoint, mr.FSType))
			sb.WriteString(fmt.Sprintf("      Description: %s\n", mr.Description))
		}
	} else {
		sb.WriteString("  - No sensitive volume exposures or writeable kernel mounts detected.\n")
	}
	sb.WriteString("\n")

	// 5. File Descriptor Leak Scan
	sb.WriteString(fmt.Sprintf("%s[5] FILE DESCRIPTOR LEAK SCAN%s (Score: %d/100)\n", Bold+Underline, Reset, r.FD.Score))
	sb.WriteString(fmt.Sprintf("  - Total File Descriptors Open: %d\n", len(r.FD.FDs)))
	hasFDRisks := false
	for _, fd := range r.FD.FDs {
		if fd.IsHighRisk {
			hasFDRisks = true
			sb.WriteString(fmt.Sprintf("    * %s%d -> %s (%s)%s\n", Red+Bold, fd.FD, fd.Target, fd.Type, Reset))
			sb.WriteString(fmt.Sprintf("      Description: %s\n", fd.Description))
		}
	}
	if !hasFDRisks {
		sb.WriteString("  - No dangerous host file descriptors or sensitive file access detected.\n")
	}
	sb.WriteString("\n")

	// 6. Environment Secret Scan
	sb.WriteString(fmt.Sprintf("%s[6] ENVIRONMENT SECRET SCAN%s (Score: %d/100)\n", Bold+Underline, Reset, r.Env.Score))
	if len(r.Env.Secrets) > 0 {
		sb.WriteString(fmt.Sprintf("  %s%sSensitive Keys Exposed:%s\n", Bold, Red, Reset))
		for _, s := range r.Env.Secrets {
			sb.WriteString(fmt.Sprintf("    * %s = %s\n", s.Key, s.Value))
		}
	} else {
		sb.WriteString("  - No sensitive environment variable patterns detected.\n")
	}
	sb.WriteString("\n")

	// 7. Sockets & Network Interfaces
	isNetShared := false
	if r.Namespaces != nil {
		for _, ns := range r.Namespaces.Namespaces {
			if ns.Name == "net" && ns.IsSharedWithHost {
				isNetShared = true
				break
			}
		}
	}

	headerTitle := "INNER-NAMESPACE NETWORK SOCKETS"
	if isNetShared {
		headerTitle = "HOST PORTS ACCESSIBLE TO CONTAINER"
	}
	sb.WriteString(fmt.Sprintf("%s[7] %s%s\n", Bold+Underline, headerTitle, Reset))
	if len(r.Network.ListeningPorts) > 0 {
		sb.WriteString("  - Active Listening Ports:\n")
		for _, lp := range r.Network.ListeningPorts {
			exposed := ""
			if lp.LocalIP == "0.0.0.0" || lp.LocalIP == "::" {
				exposed = fmt.Sprintf(" (%sEXPOSED TO NETWORK%s)", Red+Bold, Reset)
			}
			sb.WriteString(fmt.Sprintf("    * [%s] %s:%d%s\n", lp.Proto, lp.LocalIP, lp.LocalPort, exposed))
		}
	} else {
		sb.WriteString("  - No TCP listening ports inside network namespace.\n")
	}
	if len(r.Network.Connections) > 0 {
		sb.WriteString("  - Established Connections:\n")
		for _, conn := range r.Network.Connections {
			sb.WriteString(fmt.Sprintf("    * [%s] %s:%d -> %s:%d\n", conn.Proto, conn.LocalIP, conn.LocalPort, conn.RemoteIP, conn.RemotePort))
		}
	}
	sb.WriteString("\n")

	// 8. Filesystem Audit
	sb.WriteString(fmt.Sprintf("%s[8] CONTAINER FILESYSTEM AUDIT%s (Score: %d/100)\n", Bold+Underline, Reset, r.Filesystem.Score))
	if len(r.Filesystem.Risks) > 0 {
		sb.WriteString(fmt.Sprintf("  %s%sFilesystem Risks Discovered:%s\n", Bold, Red, Reset))
		for _, fr := range r.Filesystem.Risks {
			color := Red
			if fr.RiskLevel == "Medium" {
				color = Yellow
			} else if fr.RiskLevel == "Low" {
				color = Gray
			}
			sb.WriteString(fmt.Sprintf("    * %s%s%s (%s): %s\n", Bold, color, fr.Path, fr.RiskLevel, Reset+fr.Description))
		}
	} else {
		sb.WriteString("  - No sensitive SUID/SGID files, insecure permissions, or environment secrets found in filesystem.\n")
	}
	sb.WriteString("\n")

	// 9. Systemd Service Audit
	if r.Systemd != nil {
		sb.WriteString(fmt.Sprintf("%s[9] SYSTEMD SERVICE FILE AUDIT%s (Score: %d/100)\n", Bold+Underline, Reset, r.Systemd.Score))
		sb.WriteString(fmt.Sprintf("  - Service Unit : %s%s%s\n", Bold, r.Systemd.UnitName, Reset))
		if r.Systemd.FilePath != "" {
			sb.WriteString(fmt.Sprintf("  - File Path    : %s\n", r.Systemd.FilePath))
		}
		if len(r.Systemd.DropinFiles) > 0 {
			sb.WriteString(fmt.Sprintf("  - Drop-in Files: %s\n", strings.Join(r.Systemd.DropinFiles, ", ")))
		}
		sb.WriteString("  - Hardening Directives Audit:\n")
		for _, d := range r.Systemd.Directives {
			if d.IsSecure {
				sb.WriteString(fmt.Sprintf("    %s[✓]%s %-24s : %s%s%s\n", Green, Reset, d.Name, Green, d.CurrentValue, Reset))
			} else {
				curVal := d.CurrentValue
				if curVal == "" {
					curVal = "missing"
				}
				sb.WriteString(fmt.Sprintf("    %s[✗]%s %-24s : %s%-12s%s | Rec: %s\n", Red, Reset, d.Name, Red, curVal, Reset, d.RecommendedValue))
			}
		}
		if r.Systemd.SuggestedUnitSnippet != "" {
			sb.WriteString(fmt.Sprintf("  %sSuggested Hardened [Service] Override Snippet:%s\n", Gray, Reset))
			lines := strings.Split(r.Systemd.SuggestedUnitSnippet, "\n")
			for _, line := range lines {
				if line != "" {
					sb.WriteString(fmt.Sprintf("    %s%s%s\n", Cyan, line, Reset))
				}
			}
		}
		sb.WriteString("\n")
	}

	// 10. Process Hierarchy & Container Tree
	if r.ProcessTree != nil && r.ProcessTree.TreeASCII != "" {
		sb.WriteString(fmt.Sprintf("%s[10] PROCESS HIERARCHY & CONTAINER TREE%s (Nodes: %d)\n", Bold+Underline, Reset, r.ProcessTree.TotalNodes))
		lines := strings.Split(strings.TrimSpace(r.ProcessTree.TreeASCII), "\n")
		for _, line := range lines {
			if strings.Contains(line, "[TARGET PROCESS]") {
				sb.WriteString(fmt.Sprintf("  %s%s%s\n", Bold+Cyan, line, Reset))
			} else if strings.Contains(line, "[Container Init/Shim]") {
				sb.WriteString(fmt.Sprintf("  %s%s%s\n", Yellow, line, Reset))
			} else {
				sb.WriteString(fmt.Sprintf("  %s\n", line))
			}
		}
		sb.WriteString("\n")
	}

	// Summary Recommendation
	recs := append([]string{}, r.Security.Recommendations...)
	if r.Mounts != nil {
		recs = append(recs, r.Mounts.Recommendations...)
	}
	if r.Filesystem != nil {
		recs = append(recs, r.Filesystem.Recommendations...)
	}
	if r.Systemd != nil {
		recs = append(recs, r.Systemd.Recommendations...)
	}
	if len(r.Env.Secrets) > 0 {
		recs = append(recs, "Do not expose passwords, API keys, or security tokens in environment variables. Use secret stores (e.g. Docker Secrets, K8s Secrets, HashiCorp Vault) or mount credentials securely as files.")
	}
	for _, fd := range r.FD.FDs {
		if fd.IsHighRisk && fd.Type == "Directory" {
			recs = append(recs, "Ensure file descriptors pointing to host directories are closed before spawning container processes (ensure O_CLOEXEC is set on host file descriptors).")
			break
		}
	}

	if len(recs) > 0 {
		sb.WriteString(fmt.Sprintf("%sRECOMMENDED REMEDIATIONS%s\n", Bold+Underline, Reset))
		for i, rec := range recs {
			sb.WriteString(fmt.Sprintf("  %d. %s\n", i+1, rec))
		}
		sb.WriteString("\n")
	}

	// 11. Auto-Generated Hardening Artifacts & Snippets
	if r.Remediations != nil {
		sb.WriteString(fmt.Sprintf("%s[11] AUTO-GENERATED HARDENING ARTIFACTS & OVERRIDES%s\n", Bold+Underline, Reset))
		
		if r.Remediations.SystemdOverride != "" {
			sb.WriteString(fmt.Sprintf("  %s%sSystemd Service Drop-In Override (%s):%s\n", Bold, Cyan, r.Remediations.SystemdOverridePath, Reset))
			for _, l := range strings.Split(strings.TrimSpace(r.Remediations.SystemdOverride), "\n") {
				sb.WriteString(fmt.Sprintf("    %s\n", l))
			}
			sb.WriteString("\n")
		}

		if r.Remediations.DockerCLI != "" {
			sb.WriteString(fmt.Sprintf("  %s%sHardened Docker Run Command:%s\n", Bold, Cyan, Reset))
			for _, l := range strings.Split(r.Remediations.DockerCLI, "\n") {
				sb.WriteString(fmt.Sprintf("    %s\n", l))
			}
			sb.WriteString("\n")
		}

		if r.Remediations.DockerCompose != "" {
			sb.WriteString(fmt.Sprintf("  %s%sHardened Docker Compose Service Snippet:%s\n", Bold, Cyan, Reset))
			for _, l := range strings.Split(r.Remediations.DockerCompose, "\n") {
				sb.WriteString(fmt.Sprintf("    %s\n", l))
			}
			sb.WriteString("\n")
		}

		if r.Remediations.KubernetesYAML != "" {
			sb.WriteString(fmt.Sprintf("  %s%sKubernetes Hardened SecurityContext Manifest:%s\n", Bold, Cyan, Reset))
			for _, l := range strings.Split(r.Remediations.KubernetesYAML, "\n") {
				sb.WriteString(fmt.Sprintf("    %s\n", l))
			}
			sb.WriteString("\n")
		}

		if r.Remediations.SysctlConf != "" {
			sb.WriteString(fmt.Sprintf("  %s%sHost Sysctl Hardening Configuration (/etc/sysctl.d/99-nspect-hardening.conf):%s\n", Bold, Cyan, Reset))
			for _, l := range strings.Split(strings.TrimSpace(r.Remediations.SysctlConf), "\n") {
				sb.WriteString(fmt.Sprintf("    %s\n", l))
			}
			sb.WriteString("\n")
		}
	}

	// 12. Potential Container & Kernel CVE Exposure Matrix
	if len(r.CVEs) > 0 {
		sb.WriteString(fmt.Sprintf("%s[12] POTENTIAL CONTAINER & KERNEL CVE EXPOSURES%s (%d Detected)\n", Bold+Underline, Reset, len(r.CVEs)))
		for _, cve := range r.CVEs {
			color := Yellow
			if cve.Severity == "CRITICAL" || cve.Severity == "HIGH" {
				color = Red
			}
			sb.WriteString(fmt.Sprintf("  %s%-16s%s [%s%-8s%s] Component: %s\n", Bold, cve.ID, Reset, color, cve.Severity, Reset, cve.Component))
			sb.WriteString(fmt.Sprintf("    Title      : %s\n", cve.Title))
			sb.WriteString(fmt.Sprintf("    Vector     : %s\n", cve.ExploitVector))
			sb.WriteString(fmt.Sprintf("    Mitigation : %s\n", cve.Mitigation))
			sb.WriteString(fmt.Sprintf("    Reference  : %s%s%s\n\n", Blue+Underline, cve.URL, Reset))
		}
	}

	return sb.String()
}

// Underline text formatting
const Underline = "\033[4m"
