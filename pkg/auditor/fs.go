package auditor

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"nspect/pkg/util"
)

// FilesystemRisk details a filesystem-related risk (e.g. SUID, world-writable).
type FilesystemRisk struct {
	Path        string `json:"path"`
	RiskLevel   string `json:"risk_level"` // Critical, High, Medium, Low
	Description string `json:"description"`
}

// FilesystemAuditResult represents the results of filesystem checks.
type FilesystemAuditResult struct {
	Risks           []FilesystemRisk `json:"risks"`
	Recommendations []string         `json:"recommendations"`
	Score           int              `json:"score"` // 0 to 100
}

// AuditFilesystem scans the target container's internal filesystem via /proc/[pid]/root.
func AuditFilesystem(pid int) (*FilesystemAuditResult, error) {
	rootPath := util.ProcPath(pid, "root")
	
	// Verify we can access the root path of the container
	if _, err := os.Stat(rootPath); err != nil {
		return &FilesystemAuditResult{
			Risks:           nil,
			Recommendations: []string{"Filesystem audit skipped: target container root filesystem is not accessible (insufficient permissions or target exited)."},
			Score:           100,
		}, nil
	}

	var risks []FilesystemRisk
	var recs []string
	scoreReduction := 0

	// 1. SUID/SGID Binary Scanner in common directories
	binaryDirs := []string{
		"/bin",
		"/sbin",
		"/usr/bin",
		"/usr/sbin",
		"/usr/local/bin",
		"/usr/local/sbin",
	}

	foundSUID := 0
	for _, dir := range binaryDirs {
		targetDir := filepath.Join(rootPath, dir)
		// Check if directory exists
		if _, err := os.Stat(targetDir); err != nil {
			continue
		}

		// Read the directory contents
		entries, err := os.ReadDir(targetDir)
		if err != nil {
			continue
		}

		for _, entry := range entries {
			// Skip directories
			if entry.IsDir() {
				continue
			}

			filePath := filepath.Join(targetDir, entry.Name())
			info, err := os.Lstat(filePath)
			if err != nil {
				continue
			}

			// We want to skip symlinks
			if info.Mode()&os.ModeSymlink != 0 {
				continue
			}

			// Check for SUID or SGID bits
			mode := info.Mode()
			if mode&os.ModeSetuid != 0 || mode&os.ModeSetgid != 0 {
				containerPath := filepath.Join(dir, entry.Name())
				
				// Standard SUID binaries like passwd, sudo, gpasswd, newgrp etc. are common,
				// but in a minimal container they shouldn't even be present.
				riskLvl := "Medium"
				desc := fmt.Sprintf("SUID/SGID binary found inside container: %s. If an attacker gains code execution as a non-root user inside the container, they can exploit vulnerability in this binary to escalate to container root.", containerPath)
				
				// Highlight highly dangerous ones if they aren't standard or if they are known risk factors
				lowerName := strings.ToLower(entry.Name())
				if lowerName == "sudo" || lowerName == "su" || lowerName == "chsh" || lowerName == "chfn" {
					riskLvl = "High"
				}

				risks = append(risks, FilesystemRisk{
					Path:        containerPath,
					RiskLevel:   riskLvl,
					Description: desc,
				})
				foundSUID++
			}
		}
	}

	if foundSUID > 0 {
		recs = append(recs, fmt.Sprintf("Remove unnecessary SUID/SGID binaries (found %d) from the container image, or run the container with '--security-opt=no-new-privileges' to block SUID execution.", foundSUID))
		scoreReduction += foundSUID * 3
		if scoreReduction > 30 {
			scoreReduction = 30
		}
	}

	// 2. Sensitive File Permissions Check
	sensitiveFiles := []struct {
		Path        string
		CheckWrite  bool
		CheckOthers bool // Check if readable/writable by others
		Description string
	}{
		{"/etc/shadow", false, true, "Shadow file is readable or writable by non-root users inside the container namespace."},
		{"/etc/passwd", true, false, "Passwd file is writable by non-root users inside the container namespace."},
		{"/etc/hosts", true, false, "Hosts file is writable, allowing DNS spoofing inside the container namespace."},
		{"/etc/resolv.conf", true, false, "Resolv.conf file is writable, allowing DNS hijacking inside the container namespace."},
	}

	for _, sf := range sensitiveFiles {
		targetFile := filepath.Join(rootPath, sf.Path)
		info, err := os.Stat(targetFile)
		if err != nil {
			continue
		}

		mode := info.Mode()
		isVulnerable := false
		var vulnDesc []string

		if sf.CheckWrite && (mode&0002 != 0) { // World-writable
			isVulnerable = true
			vulnDesc = append(vulnDesc, "world-writable (mode allows any user to modify)")
		}

		if sf.CheckOthers && (mode&0007 != 0) { // Readable/writable/executable by others
			isVulnerable = true
			vulnDesc = append(vulnDesc, fmt.Sprintf("insecure permissions (mode: %04o, should be restricted to root only)", mode.Perm()))
		}

		if isVulnerable {
			risks = append(risks, FilesystemRisk{
				Path:        sf.Path,
				RiskLevel:   "High",
				Description: fmt.Sprintf("%s The file is %s.", sf.Description, strings.Join(vulnDesc, " and ")),
			})
			recs = append(recs, fmt.Sprintf("Restrict permissions on '%s' inside the container image (e.g. chmod 600 /etc/shadow, chmod 644 /etc/passwd).", sf.Path))
			scoreReduction += 15
		}
	}

	// 3. Scan for common configuration files with secrets (just look for .env, credentials files in root/app)
	secretFilesPattern := []string{
		"/.env",
		"/app/.env",
		"/var/www/html/.env",
	}
	foundSecrets := 0
	for _, spf := range secretFilesPattern {
		targetFile := filepath.Join(rootPath, spf)
		if _, err := os.Stat(targetFile); err == nil {
			// Found an env file in the container
			risks = append(risks, FilesystemRisk{
				Path:        spf,
				RiskLevel:   "High",
				Description: fmt.Sprintf("Environment file '%s' detected inside the container filesystem. Hardcoding secrets in container filesystem violates credential hygiene rules.", spf),
			})
			foundSecrets++
		}
	}
	if foundSecrets > 0 {
		recs = append(recs, "Do not package environment files (.env) or hardcoded credentials inside the container image. Inject configuration values at runtime using secure environment variables or secret mounts.")
		scoreReduction += 15
	}

	finalScore := 100 - scoreReduction
	if finalScore < 0 {
		finalScore = 0
	}

	return &FilesystemAuditResult{
		Risks:           risks,
		Recommendations: recs,
		Score:           finalScore,
	}, nil
}
