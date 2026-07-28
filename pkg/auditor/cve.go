package auditor

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// CVEFinding describes a specific CVE risk matched against process audit metrics.
type CVEFinding struct {
	ID            string   `json:"id"`
	Title         string   `json:"title"`
	Severity      string   `json:"severity"` // "CRITICAL", "HIGH", "MEDIUM", "LOW"
	CVSSScore     float64  `json:"cvss_score,omitempty"`
	Component     string   `json:"component"`
	Description   string   `json:"description"`
	ExploitVector string   `json:"exploit_vector"`
	Mitigation    string   `json:"mitigation"`
	URL           string   `json:"url"` // Primary NVD/Advisory link
	References    []string `json:"references,omitempty"`
}

// CVERule defines runtime evaluation triggers for matching a CVE.
type CVERule struct {
	CVE                 CVEFinding `json:"cve"`
	RequireHostFDLeak   bool       `json:"require_host_fd_leak,omitempty"`
	RequireCAPSysAdmin  bool       `json:"require_cap_sys_admin,omitempty"`
	RequireCAPBPF       bool       `json:"require_cap_bpf,omitempty"`
	RequireCAPPtrace    bool       `json:"require_cap_ptrace,omitempty"`
	RequireCAPNetRaw    bool       `json:"require_cap_net_raw,omitempty"`
	RequireCAPNetAdmin  bool       `json:"require_cap_net_admin,omitempty"`
	RequireWritableProc bool       `json:"require_writable_proc,omitempty"`
	RequireWritableSys  bool       `json:"require_writable_sys,omitempty"`
	RequireSharedNetNS  bool       `json:"require_shared_net_ns,omitempty"`
	RequireHostRootEUID bool       `json:"require_host_root_euid,omitempty"`
	RequireNoNewPrivsNo    bool       `json:"require_no_new_privs_no,omitempty"`
	RequireUnprivUserNS    bool       `json:"require_unpriv_userns,omitempty"`
	RequireSUIDBinaries    bool       `json:"require_suid_binaries,omitempty"`
	RequireSecretsExposed  bool       `json:"require_secrets_exposed,omitempty"`
	RequireSeccompDisabled bool       `json:"require_seccomp_disabled,omitempty"`
	RequireContainerized   bool       `json:"require_containerized,omitempty"`
	RequireContainerRuntime bool      `json:"require_container_runtime,omitempty"`
	RequireKubernetes       bool      `json:"require_kubernetes,omitempty"`
}

// CVEDatabase represents the full rule collection.
type CVEDatabase struct {
	LastUpdated string    `json:"last_updated"`
	Rules       []CVERule `json:"rules"`
}

// GetUserDBPath returns the local custom database file path (~/.nspect/cve_db.json).
func GetUserDBPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "/tmp"
	}
	return filepath.Join(home, ".nspect", "cve_db.json")
}

// LoadCVEDatabase loads custom local DB if present, falling back to embedded default rules.
func LoadCVEDatabase() *CVEDatabase {
	userPath := GetUserDBPath()
	if data, err := os.ReadFile(userPath); err == nil {
		var db CVEDatabase
		if err := json.Unmarshal(data, &db); err == nil && len(db.Rules) > 0 {
			return &db
		}
	}
	return GetDefaultCVEDatabase()
}

// EvaluateCVEs checks report findings against the loaded CVE database rules.
func EvaluateCVEs(report *AuditReport) []CVEFinding {
	db := LoadCVEDatabase()
	var findings []CVEFinding

	hasFDLeak := false
	if report.FD != nil {
		for _, fd := range report.FD.FDs {
			if fd.IsHighRisk && fd.Type == "Directory" {
				hasFDLeak = true
				break
			}
		}
	}

	hasSysAdmin := false
	hasBPF := false
	hasPtrace := false
	hasNetRaw := false
	hasNetAdmin := false
	if report.Capabilities != nil {
		for _, capName := range report.Capabilities.Sets.Effective {
			switch capName {
			case "CAP_SYS_ADMIN":
				hasSysAdmin = true
			case "CAP_BPF":
				hasBPF = true
			case "CAP_SYS_PTRACE":
				hasPtrace = true
			case "CAP_NET_RAW":
				hasNetRaw = true
			case "CAP_NET_ADMIN":
				hasNetAdmin = true
			}
		}
	}

	isHostRoot := report.Security != nil && report.Security.EUID == 0 && !report.Security.UserNSMapped
	noNewPrivsNo := report.Security != nil && !report.Security.NoNewPrivs

	isSharedNet := false
	if report.Namespaces != nil {
		for _, ns := range report.Namespaces.Namespaces {
			if ns.Name == "net" && ns.IsSharedWithHost {
				isSharedNet = true
				break
			}
		}
	}

	hasWritableProc := false
	hasWritableSys := false
	if report.Mounts != nil {
		for _, m := range report.Mounts.Risks {
			if strings.HasPrefix(m.MountPoint, "/proc") && (m.RiskLevel == "Critical" || m.RiskLevel == "High") {
				hasWritableProc = true
			}
			if strings.HasPrefix(m.MountPoint, "/sys") && (m.RiskLevel == "Critical" || m.RiskLevel == "High") {
				hasWritableSys = true
			}
		}
	}

	hasUnprivUserNS := false
	if report.Kernel != nil {
		for _, s := range report.Kernel.Sysctls {
			if s.Key == "kernel.unprivileged_userns_clone" && s.CurrentValue == "1" {
				hasUnprivUserNS = true
			}
		}
	}

	hasSUID := false
	if report.Filesystem != nil {
		for _, r := range report.Filesystem.Risks {
			if strings.Contains(r.Description, "SUID") || strings.Contains(r.Description, "SGID") {
				hasSUID = true
				break
			}
		}
	}
	hasSecrets := report.Env != nil && len(report.Env.Secrets) > 0
	isSeccompDisabled := report.Security != nil && report.Security.SeccompMode == 0

	isContainerized := false
	if report.Namespaces != nil {
		for _, ns := range report.Namespaces.Namespaces {
			if (ns.Name == "pid" || ns.Name == "uts" || ns.Name == "ipc") && !ns.IsSharedWithHost {
				isContainerized = true
				break
			}
		}
	}
	if report.Security != nil && report.Security.UserNSMapped {
		isContainerized = true
	}

	hasContainerRuntime := false
	if report.ProcessTree != nil {
		for _, node := range report.ProcessTree.AncestorChain {
			name := strings.ToLower(node.Name)
			if strings.Contains(name, "containerd") || strings.Contains(name, "dockerd") || strings.Contains(name, "crio") || strings.Contains(name, "podman") || strings.Contains(name, "runc") || strings.Contains(name, "crun") || strings.Contains(name, "lxc") {
				hasContainerRuntime = true
				break
			}
		}
	}

	isKubernetes := false
	if report.Env != nil {
		for _, sec := range report.Env.Secrets {
			if strings.Contains(sec.Key, "KUBERNETES") {
				isKubernetes = true
				break
			}
		}
	}
	if report.ProcessTree != nil {
		for _, node := range report.ProcessTree.AncestorChain {
			name := strings.ToLower(node.Name)
			cmd := strings.ToLower(node.Cmdline)
			if strings.Contains(name, "kubelet") || strings.Contains(name, "k8s") || strings.Contains(cmd, "kubelet") || strings.Contains(cmd, "kubepods") {
				isKubernetes = true
				break
			}
		}
	}

	for _, rule := range db.Rules {
		matched := true

		if rule.RequireContainerized && !isContainerized {
			matched = false
		}
		if rule.RequireContainerRuntime && !hasContainerRuntime {
			matched = false
		}
		if rule.RequireKubernetes && !isKubernetes {
			matched = false
		}
		if rule.RequireHostFDLeak && !hasFDLeak {
			matched = false
		}
		if rule.RequireCAPSysAdmin && !hasSysAdmin {
			matched = false
		}
		if rule.RequireCAPBPF && !hasBPF {
			matched = false
		}
		if rule.RequireCAPPtrace && !hasPtrace {
			matched = false
		}
		if rule.RequireCAPNetRaw && !hasNetRaw {
			matched = false
		}
		if rule.RequireCAPNetAdmin && !hasNetAdmin {
			matched = false
		}
		if rule.RequireWritableProc && !hasWritableProc {
			matched = false
		}
		if rule.RequireWritableSys && !hasWritableSys {
			matched = false
		}
		if rule.RequireSharedNetNS && !isSharedNet {
			matched = false
		}
		if rule.RequireHostRootEUID && !isHostRoot {
			matched = false
		}
		if rule.RequireNoNewPrivsNo && !noNewPrivsNo {
			matched = false
		}
		if rule.RequireUnprivUserNS && !hasUnprivUserNS {
			matched = false
		}
		if rule.RequireSUIDBinaries && !hasSUID {
			matched = false
		}
		if rule.RequireSecretsExposed && !hasSecrets {
			matched = false
		}
		if rule.RequireSeccompDisabled && !isSeccompDisabled {
			matched = false
		}

		if matched {
			findings = append(findings, rule.CVE)
		}
	}

	return findings
}

// SyncCVEDatabase fetches the latest CVE definitions online and writes to ~/.nspect/cve_db.json.
func SyncCVEDatabase() error {
	userPath := GetUserDBPath()
	dir := filepath.Dir(userPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed creating directory %s: %w", dir, err)
	}

	// Try fetching live feed from nspect official release feed
	feedURL := "https://raw.githubusercontent.com/davidvhk/nspect/main/cve_db.json"
	client := &http.Client{Timeout: 10 * time.Second}

	resp, err := client.Get(feedURL)
	if err != nil || resp.StatusCode != http.StatusOK {
		// Fallback to generating fresh file from embedded rules
		db := GetDefaultCVEDatabase()
		db.LastUpdated = time.Now().Format("2006-01-02 15:04:05 UTC")
		data, err := json.MarshalIndent(db, "", "  ")
		if err != nil {
			return err
		}
		return os.WriteFile(userPath, data, 0600)
	}
	defer resp.Body.Close()

	var db CVEDatabase
	if err := json.NewDecoder(resp.Body).Decode(&db); err != nil || len(db.Rules) == 0 {
		db := GetDefaultCVEDatabase()
		db.LastUpdated = time.Now().Format("2006-01-02 15:04:05 UTC")
		data, _ := json.MarshalIndent(db, "", "  ")
		return os.WriteFile(userPath, data, 0600)
	}

	db.LastUpdated = time.Now().Format("2006-01-02 15:04:05 UTC")
	data, err := json.MarshalIndent(db, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(userPath, data, 0600)
}
