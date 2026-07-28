package auditor

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"nspect/pkg/util"
)

// SystemdDirectiveCheck details a single systemd security directive audit
type SystemdDirectiveCheck struct {
	Name             string `json:"name"`
	CurrentValue     string `json:"current_value"`
	IsConfigured     bool   `json:"is_configured"`
	IsSecure         bool   `json:"is_secure"`
	Description      string `json:"description"`
	RecommendedValue string `json:"recommended_value"`
}

// SystemdAuditResult contains findings for a systemd service unit file
type SystemdAuditResult struct {
	UnitName             string                  `json:"unit_name"`
	FilePath             string                  `json:"file_path"`
	FileContent          string                  `json:"file_content"`
	DropinFiles          []string                `json:"dropin_files,omitempty"`
	Directives           []SystemdDirectiveCheck `json:"directives"`
	MissingHardening     []string                `json:"missing_hardening,omitempty"`
	Recommendations      []string                `json:"recommendations,omitempty"`
	SuggestedUnitSnippet string                  `json:"suggested_unit_snippet,omitempty"`
	Score                int                     `json:"score"`
}

// Systemd directive definition
type directiveDef struct {
	Key              string
	SecureValues     []string
	Description      string
	RecommendedValue string
	RiskMsg          string
	Penalty          int
}

var systemdSecurityDirectives = []directiveDef{
	{
		Key:              "NoNewPrivileges",
		SecureValues:     []string{"yes", "true", "1"},
		Description:      "Prevents process and subprocesses from acquiring new privileges via SUID/SGID binaries",
		RecommendedValue: "NoNewPrivileges=yes",
		RiskMsg:          "NoNewPrivileges is not enabled. Subprocesses can gain new privileges via SUID binaries.",
		Penalty:          10,
	},
	{
		Key:              "ProtectSystem",
		SecureValues:     []string{"full", "strict", "yes", "true"},
		Description:      "Mounts system directories (/usr, /etc, /boot) read-only for the service",
		RecommendedValue: "ProtectSystem=strict",
		RiskMsg:          "ProtectSystem is not set to full/strict. System directories (/usr, /etc) remain writable.",
		Penalty:          10,
	},
	{
		Key:              "ProtectHome",
		SecureValues:     []string{"yes", "true", "read-only", "tmpfs"},
		Description:      "Hides or restricts access to user home directories (/home, /root, /run/user)",
		RecommendedValue: "ProtectHome=yes",
		RiskMsg:          "ProtectHome is disabled or off. User home directories are accessible by the service.",
		Penalty:          10,
	},
	{
		Key:              "PrivateTmp",
		SecureValues:     []string{"yes", "true", "1"},
		Description:      "Mounts an isolated /tmp and /var/tmp directory for the service process",
		RecommendedValue: "PrivateTmp=yes",
		RiskMsg:          "PrivateTmp is disabled. Service shares global /tmp, risking symlink attacks or file leaks.",
		Penalty:          10,
	},
	{
		Key:              "PrivateDevices",
		SecureValues:     []string{"yes", "true", "1"},
		Description:      "Replaces physical host device nodes in /dev with pseudo-devices (/dev/null, /dev/zero)",
		RecommendedValue: "PrivateDevices=yes",
		RiskMsg:          "PrivateDevices is disabled. Service can access raw physical device nodes in /dev.",
		Penalty:          10,
	},
	{
		Key:              "ProtectKernelTunables",
		SecureValues:     []string{"yes", "true", "1"},
		Description:      "Mounts /proc/sys, /sys, /proc/sysrq-trigger as read-only for the service",
		RecommendedValue: "ProtectKernelTunables=yes",
		RiskMsg:          "ProtectKernelTunables is disabled. Kernel sysctl parameters can be modified by the service.",
		Penalty:          10,
	},
	{
		Key:              "ProtectKernelModules",
		SecureValues:     []string{"yes", "true", "1"},
		Description:      "Blocks loading or unloading kernel modules (init_module / finit_module)",
		RecommendedValue: "ProtectKernelModules=yes",
		RiskMsg:          "ProtectKernelModules is disabled. Service could attempt loading custom kernel modules.",
		Penalty:          10,
	},
	{
		Key:              "ProtectControlGroups",
		SecureValues:     []string{"yes", "true", "1"},
		Description:      "Mounts /sys/fs/cgroup read-only for the service process",
		RecommendedValue: "ProtectControlGroups=yes",
		RiskMsg:          "ProtectControlGroups is disabled. Service can alter cgroup resource hierarchies.",
		Penalty:          5,
	},
	{
		Key:              "RestrictRealtime",
		SecureValues:     []string{"yes", "true", "1"},
		Description:      "Prevents acquiring realtime scheduling priority (SCHED_FIFO / SCHED_RR)",
		RecommendedValue: "RestrictRealtime=yes",
		RiskMsg:          "RestrictRealtime is disabled. Service can request realtime CPU scheduling priority.",
		Penalty:          5,
	},
	{
		Key:              "RestrictNamespaces",
		SecureValues:     []string{"yes", "true", "1", "~user"},
		Description:      "Restricts creation of new Linux namespaces (mnt, pid, net, user, ipc, uts)",
		RecommendedValue: "RestrictNamespaces=yes",
		RiskMsg:          "RestrictNamespaces is disabled. Service can create unprivileged Linux namespaces.",
		Penalty:          5,
	},
	{
		Key:              "SystemCallFilter",
		SecureValues:     []string{"*"}, // Any non-empty value
		Description:      "Enforces Seccomp system call filtering for the systemd service unit",
		RecommendedValue: "SystemCallFilter=@system-service ~@clock ~@module ~@raw-io ~@reboot ~@swap",
		RiskMsg:          "SystemCallFilter is missing. Service can execute any Linux system call.",
		Penalty:          10,
	},
	{
		Key:              "MemoryMax",
		SecureValues:     []string{"*"},
		Description:      "Enforces cgroup memory limit to prevent memory exhaustion and DoS",
		RecommendedValue: "MemoryMax=512M",
		RiskMsg:          "MemoryMax limit is not specified. Memory leaks could cause host memory exhaustion.",
		Penalty:          5,
	},
}

// FindSystemdUnitName inspects /proc/[pid]/cgroup and process name to find systemd service name
func FindSystemdUnitName(pid int, procName string) string {
	cgroupPath := util.ProcPath(pid, "cgroup")
	data, err := os.ReadFile(cgroupPath)
	if err == nil {
		re := regexp.MustCompile(`([a-zA-Z0-9_\-@\.]+\.service)`)
		matches := re.FindStringSubmatch(string(data))
		if len(matches) > 1 {
			return matches[1]
		}
	}

	if procName != "" && procName != "unknown" {
		unitName := procName + ".service"
		if locateUnitFile(unitName) != "" {
			return unitName
		}
	}

	return ""
}

// locateUnitFile searches standard systemd directories for unit file
func locateUnitFile(unitName string) string {
	searchPaths := []string{
		filepath.Join("/etc/systemd/system", unitName),
		filepath.Join("/run/systemd/system", unitName),
		filepath.Join("/usr/lib/systemd/system", unitName),
		filepath.Join("/lib/systemd/system", unitName),
	}

	for _, path := range searchPaths {
		if fileExists(path) {
			return path
		}
	}
	return ""
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// findDropinFiles locates systemd override drop-in files (.conf)
func findDropinFiles(unitName string) []string {
	searchDirs := []string{
		filepath.Join("/etc/systemd/system", unitName+".d"),
		filepath.Join("/run/systemd/system", unitName+".d"),
		filepath.Join("/usr/lib/systemd/system", unitName+".d"),
	}

	var dropins []string
	for _, dir := range searchDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".conf") {
				dropins = append(dropins, filepath.Join(dir, entry.Name()))
			}
		}
	}
	return dropins
}

// AuditSystemd inspects the systemd service file for a target PID
func AuditSystemd(pid int, procName string) (*SystemdAuditResult, error) {
	unitName := FindSystemdUnitName(pid, procName)
	if unitName == "" {
		return nil, nil // Not a systemd service unit
	}

	filePath := locateUnitFile(unitName)
	if filePath == "" {
		return &SystemdAuditResult{
			UnitName: unitName,
			Score:    50,
		}, nil
	}

	contentBytes, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read unit file %s: %w", filePath, err)
	}

	contentStr := string(contentBytes)
	dropins := findDropinFiles(unitName)

	fullContentStr := contentStr
	for _, dropin := range dropins {
		if dropinData, err := os.ReadFile(dropin); err == nil {
			fullContentStr += "\n# Drop-in Override: " + dropin + "\n" + string(dropinData)
		}
	}

	// Parse directives from unit file and drop-ins
	parsedKv := parseSystemdDirectives(fullContentStr)

	var directiveChecks []SystemdDirectiveCheck
	var missingHardening []string
	var recommendations []string
	score := 100

	var snippetBuilder strings.Builder
	snippetBuilder.WriteString("[Service]\n# Recommended Systemd Hardening Overrides\n")
	snippetBuilder.WriteString(fmt.Sprintf("# Save to /etc/systemd/system/%s.d/override.conf\n", unitName))

	for _, def := range systemdSecurityDirectives {
		val, isFound := parsedKv[def.Key]
		isSecure := false

		if isFound {
			valLower := strings.ToLower(val)
			if def.SecureValues[0] == "*" {
				if valLower != "" && valLower != "no" && valLower != "false" && valLower != "off" && valLower != "0" {
					isSecure = true
				}
			} else {
				for _, secVal := range def.SecureValues {
					if valLower == secVal {
						isSecure = true
						break
					}
				}
			}
		}

		if !isSecure {
			score -= def.Penalty
			missingHardening = append(missingHardening, def.RiskMsg)
			recommendations = append(recommendations, fmt.Sprintf("Add '%s' to [Service] section in systemd unit file %s.", def.RecommendedValue, filePath))
			snippetBuilder.WriteString(def.RecommendedValue + "\n")
		}

		displayVal := val
		if !isFound {
			displayVal = "MISSING"
		} else if isSecure {
			valUpper := strings.ToUpper(val)
			if valUpper == "YES" || valUpper == "TRUE" || valUpper == "1" || valUpper == "" {
				displayVal = "YES"
			} else {
				displayVal = valUpper
			}
		} else {
			valUpper := strings.ToUpper(val)
			if valUpper == "NO" || valUpper == "FALSE" || valUpper == "0" || valUpper == "" {
				displayVal = "NO"
			} else {
				displayVal = "DISABLED"
			}
		}

		directiveChecks = append(directiveChecks, SystemdDirectiveCheck{
			Name:             def.Key,
			CurrentValue:     displayVal,
			IsConfigured:     isFound,
			IsSecure:         isSecure,
			Description:      def.Description,
			RecommendedValue: def.RecommendedValue,
		})
	}

	if score < 0 {
		score = 0
	}

	return &SystemdAuditResult{
		UnitName:             unitName,
		FilePath:             filePath,
		FileContent:          contentStr,
		DropinFiles:          dropins,
		Directives:           directiveChecks,
		MissingHardening:     missingHardening,
		Recommendations:      recommendations,
		SuggestedUnitSnippet: snippetBuilder.String(),
		Score:                score,
	}, nil
}

// parseSystemdDirectives extracts Key=Value pairs from systemd unit files
func parseSystemdDirectives(content string) map[string]string {
	result := make(map[string]string)
	lines := strings.Split(content, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			val := strings.TrimSpace(parts[1])
			// If key appears multiple times (e.g. SystemCallFilter), concatenate
			if existing, ok := result[key]; ok {
				result[key] = existing + " " + val
			} else {
				result[key] = val
			}
		}
	}

	return result
}
