package auditor

import (
	"encoding/json"
	"fmt"
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
		envResult = &EnvAuditResult{Secrets: nil, Score: 100}
	}

	netResult, err := AuditNetwork(pid)
	if err != nil {
		netResult = &NetAuditResult{ListeningPorts: nil, Connections: nil}
	}

	fdResult, err := AuditFD(pid)
	if err != nil {
		fdResult = &FDAuditResult{FDs: nil, Score: 100}
	}

	// Calculate overall score (weighted average)
	// Weights: Namespaces (25%), Capabilities (25%), Mounts (15%), Security Context (15%), Env (10%), FD (10%)
	overall := (nsResult.Score*25 + capResult.Score*25 + mountResult.Score*15 + secResult.Score*15 + envResult.Score*10 + fdResult.Score*10) / 100

	return &AuditReport{
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
		OverallScore: overall,
	}, nil
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
	} else if r.Security.SeccompMode == 1 {
		seccompDesc = "Enabled (Strict)"
		seccompColor = Green
	}
	sb.WriteString(fmt.Sprintf("  - Seccomp      : %s%s%s\n", seccompColor, seccompDesc, Reset))

	nnpStatus := fmt.Sprintf("%sNo%s", Red, Reset)
	if r.Security.NoNewPrivs {
		nnpStatus = fmt.Sprintf("%sYes%s", Green, Reset)
	}
	sb.WriteString(fmt.Sprintf("  - NoNewPrivs   : %s\n", nnpStatus))
	sb.WriteString(fmt.Sprintf("  - LSM Status   : %s\n", r.Security.LSMProfile))

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
	sb.WriteString(fmt.Sprintf("%s[7] INNER-NAMESPACE NETWORK SOCKETS%s\n", Bold+Underline, Reset))
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

	// Summary Recommendation
	recs := append([]string{}, r.Security.Recommendations...)
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

	return sb.String()
}

// Underline text formatting
const Underline = "\033[4m"
