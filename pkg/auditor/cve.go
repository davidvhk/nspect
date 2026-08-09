package auditor

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
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

		// Ensure rules without specific kernel trigger flags require exact component/process name matching
		hasSpecificCondition := rule.RequireHostFDLeak || rule.RequireCAPSysAdmin || rule.RequireCAPBPF ||
			rule.RequireCAPPtrace || rule.RequireCAPNetRaw || rule.RequireCAPNetAdmin ||
			rule.RequireWritableProc || rule.RequireWritableSys || rule.RequireSharedNetNS ||
			rule.RequireHostRootEUID || rule.RequireNoNewPrivsNo || rule.RequireUnprivUserNS ||
			rule.RequireSUIDBinaries || rule.RequireSecretsExposed || rule.RequireSeccompDisabled ||
			rule.RequireKubernetes || rule.RequireContainerRuntime

		if !hasSpecificCondition && matched {
			comp := strings.ToLower(rule.CVE.Component)
			pName := strings.ToLower(report.ProcessName)
			cmdLine := strings.ToLower(report.Cmdline)
			if comp != "" && !strings.Contains(pName, comp) && !strings.Contains(cmdLine, comp) {
				matched = false
			}
		}

		if matched {
			findings = append(findings, rule.CVE)
		}
	}

	return findings
}

type NVDResponse struct {
	Vulnerabilities []struct {
		CVE struct {
			ID          string `json:"id"`
			Descriptions []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"descriptions"`
			Metrics struct {
				CvssMetricV31 []struct {
					CvssData struct {
						BaseScore    float64 `json:"baseScore"`
						BaseSeverity string  `json:"baseSeverity"`
					} `json:"cvssData"`
				} `json:"cvssMetricV31"`
			} `json:"metrics"`
			References []struct {
				URL string `json:"url"`
			} `json:"references"`
		} `json:"cve"`
	} `json:"vulnerabilities"`
}

// FetchNVDDetails fetches live NIST NVD API 2.0 data for a specific CVE ID.
func FetchNVDDetails(cveID string, apiKey string) (*CVEFinding, error) {
	url := fmt.Sprintf("https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=%s", cveID)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "nspect-auditor/1.0")
	if apiKey != "" {
		req.Header.Set("apiKey", apiKey)
	}

	client := &http.Client{Timeout: 8 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("NVD API returned HTTP %d", resp.StatusCode)
	}

	var nvdRes NVDResponse
	if err := json.NewDecoder(resp.Body).Decode(&nvdRes); err != nil || len(nvdRes.Vulnerabilities) == 0 {
		return nil, fmt.Errorf("no NVD vulnerability records found for %s", cveID)
	}

	vuln := nvdRes.Vulnerabilities[0].CVE
	finding := &CVEFinding{
		ID:  vuln.ID,
		URL: fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", vuln.ID),
	}

	for _, desc := range vuln.Descriptions {
		if desc.Lang == "en" {
			finding.Description = desc.Value
			break
		}
	}

	if len(vuln.Metrics.CvssMetricV31) > 0 {
		cvss := vuln.Metrics.CvssMetricV31[0].CvssData
		finding.CVSSScore = cvss.BaseScore
		finding.Severity = strings.ToUpper(cvss.BaseSeverity)
	}

	var refs []string
	for _, ref := range vuln.References {
		if ref.URL != "" {
			refs = append(refs, ref.URL)
			if len(refs) >= 5 {
				break
			}
		}
	}
	finding.References = refs

	return finding, nil
}

// FetchNVDKeywordCVEs queries NIST NVD API 2.0 for live CVEs matching a container/kernel keyword and optional sinceDate.
func FetchNVDKeywordCVEs(keyword string, apiKey string, sinceDate string) ([]CVERule, error) {
	kwEscaped := url.QueryEscape(strings.TrimSpace(keyword))
	apiURL := fmt.Sprintf("https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=%s&resultsPerPage=20", kwEscaped)
	if sinceDate != "" {
		sinceDate = strings.TrimSpace(sinceDate)
		if len(sinceDate) == 10 { // e.g. 2020-01-01
			apiURL += fmt.Sprintf("&pubStartDate=%sT00:00:00.000", sinceDate)
		} else if strings.Contains(sinceDate, "T") {
			apiURL += fmt.Sprintf("&pubStartDate=%s", sinceDate)
		}
	}

	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "nspect-auditor/1.0")
	if apiKey != "" {
		req.Header.Set("apiKey", apiKey)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("NVD API returned HTTP %d", resp.StatusCode)
	}

	var nvdRes NVDResponse
	if err := json.NewDecoder(resp.Body).Decode(&nvdRes); err != nil {
		return nil, err
	}

	var newRules []CVERule
	for _, item := range nvdRes.Vulnerabilities {
		vuln := item.CVE
		desc := ""
		for _, d := range vuln.Descriptions {
			if d.Lang == "en" {
				desc = d.Value
				break
			}
		}

		score := 7.5
		sev := "HIGH"
		if len(vuln.Metrics.CvssMetricV31) > 0 {
			score = vuln.Metrics.CvssMetricV31[0].CvssData.BaseScore
			sev = strings.ToUpper(vuln.Metrics.CvssMetricV31[0].CvssData.BaseSeverity)
		}

		var refs []string
		for _, r := range vuln.References {
			if r.URL != "" {
				refs = append(refs, r.URL)
				if len(refs) >= 3 {
					break
				}
			}
		}

		rule := CVERule{
			CVE: CVEFinding{
				ID:            vuln.ID,
				Title:         fmt.Sprintf("Live NVD Advisory: %s (%s)", vuln.ID, keyword),
				Severity:      sev,
				CVSSScore:     score,
				Component:     keyword,
				Description:   desc,
				ExploitVector: fmt.Sprintf("Discovered via NIST NVD search for '%s'", keyword),
				Mitigation:    "Update component to latest security patch.",
				URL:           fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", vuln.ID),
				References:    refs,
			},
			RequireContainerized: true,
		}

		kwLower := strings.ToLower(keyword)
		switch kwLower {
		case "runc", "containerd", "crio", "podman":
			rule.RequireContainerRuntime = true
		case "ebpf":
			rule.RequireCAPBPF = true
		case "overlayfs":
			rule.RequireUnprivUserNS = true
		case "sysctl", "kernel":
			rule.RequireCAPSysAdmin = true
		case "kubernetes", "k8s":
			rule.RequireKubernetes = true
		}

		newRules = append(newRules, rule)
	}

	return newRules, nil
}

// SyncCVEDatabase fetches the latest CVE definitions online and writes to ~/.nspect/cve_db.json.
func SyncCVEDatabase(apiKey string) error {
	return SyncCVEDatabaseEx(apiKey, "", "")
}

// SyncCVEDatabaseEx fetches live CVE definitions with custom search keywords and publication start date.
func SyncCVEDatabaseEx(apiKey string, customKeywords string, sinceDate string) error {
	userPath := GetUserDBPath()
	dir := filepath.Dir(userPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed creating directory %s: %w", dir, err)
	}

	db := GetDefaultCVEDatabase()

	// Try fetching live feed from custom feed URL or nspect official repository
	feedURL := os.Getenv("NSPECT_CVE_FEED_URL")
	if feedURL == "" {
		feedURL = "https://raw.githubusercontent.com/davidvhk/nspect/main/cve_db.json"
	}
	client := &http.Client{Timeout: 5 * time.Second}

	resp, err := client.Get(feedURL)
	if err == nil && resp.StatusCode == http.StatusOK {
		var remoteDB CVEDatabase
		if json.NewDecoder(resp.Body).Decode(&remoteDB) == nil && len(remoteDB.Rules) > 0 {
			db = &remoteDB
		}
		resp.Body.Close()
	}

	if apiKey == "" {
		apiKey = os.Getenv("NVD_API_KEY")
	}

	// Query NIST NVD API 2.0 for live container/kernel CVE discovery
	existingIDs := make(map[string]bool)
	for _, r := range db.Rules {
		existingIDs[r.CVE.ID] = true
	}

	keywords := []string{"runc", "containerd", "buildkit", "overlayfs", "ebpf"}
	if customKeywords != "" {
		userList := strings.Split(customKeywords, ",")
		var cleaned []string
		for _, k := range userList {
			k = strings.TrimSpace(k)
			if k != "" {
				cleaned = append(cleaned, k)
			}
		}
		if len(cleaned) > 0 {
			keywords = cleaned
		}
	}

	for _, kw := range keywords {
		dateMsg := ""
		if sinceDate != "" {
			dateMsg = fmt.Sprintf(" (published since %s)", sinceDate)
		}
		fmt.Printf("    - Querying NIST NVD API 2.0 for '%s'%s...\n", kw, dateMsg)
		fetched, err := FetchNVDKeywordCVEs(kw, apiKey, sinceDate)
		if err == nil && len(fetched) > 0 {
			for _, newRule := range fetched {
				if !existingIDs[newRule.CVE.ID] {
					existingIDs[newRule.CVE.ID] = true
					db.Rules = append(db.Rules, newRule)
				}
			}
		}
		time.Sleep(600 * time.Millisecond) // Respect NVD API rate limits
	}

	db.LastUpdated = time.Now().Format("2006-01-02 15:04:05 UTC")
	data, err := json.MarshalIndent(db, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(userPath, data, 0600)
}
