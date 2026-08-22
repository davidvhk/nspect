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

// ToolingInventory categorizes discovered binaries inside the container rootfs.
type ToolingInventory struct {
	TotalBinaries     int      `json:"total_binaries"`
	InstalledBinaries []string `json:"installed_binaries"`
	Shells            []string `json:"shells"`
	Downloaders       []string `json:"downloaders"`
	AdminTools        []string `json:"admin_tools"`
	Interpreters      []string `json:"interpreters"`
	Compilers         []string `json:"compilers"`
	PackageManagers   []string `json:"package_managers"`
}

// HasTool checks if a binary exists in the container filesystem.
func (t *ToolingInventory) HasTool(name string) bool {
	if t == nil {
		return false
	}
	nameLower := strings.ToLower(name)
	for _, b := range t.InstalledBinaries {
		if strings.ToLower(b) == nameLower {
			return true
		}
	}
	return false
}

// FilesystemAuditResult represents the results of filesystem checks.
type FilesystemAuditResult struct {
	IsAccessible     bool              `json:"is_accessible"`
	SUIDCount        int               `json:"suid_count"`
	IsDistroless     bool              `json:"is_distroless"`
	IsChiselled      bool              `json:"is_chiselled"`
	HasShell         bool              `json:"has_shell"`
	HasPkgManager    bool              `json:"has_pkg_manager"`
	ImageFlavor      string            `json:"image_flavor"` // "Ubuntu Rock (Pebble Managed)", "Chiselled / Distroless Minimal", "Standard Linux Distribution"
	Tooling          *ToolingInventory `json:"tooling,omitempty"`
	Risks           []FilesystemRisk   `json:"risks"`
	Recommendations []string           `json:"recommendations"`
	Score           int                `json:"score"` // 0 to 100
}

// AuditFilesystem scans the target container's internal filesystem via /proc/[pid]/root.
func AuditFilesystem(pid int) (*FilesystemAuditResult, error) {
	rootPath := util.ProcPath(pid, "root")
	
	// Verify we can access the root path of the container
	if _, err := os.Stat(rootPath); err != nil {
		procName, _ := util.GetProcessName(pid)
		isPebble := strings.Contains(strings.ToLower(procName), "pebble")
		flavor := "Standard Linux Distribution"
		if isPebble {
			flavor = "Ubuntu Rock (Pebble Managed)"
		}

		return &FilesystemAuditResult{
			IsAccessible:    false,
			SUIDCount:       0,
			IsDistroless:    isPebble,
			IsChiselled:     isPebble,
			HasShell:        !isPebble,
			HasPkgManager:   !isPebble,
			ImageFlavor:     flavor,
			Tooling: &ToolingInventory{
				TotalBinaries:     0,
				InstalledBinaries: []string{},
				Shells:            []string{},
				Downloaders:       []string{},
				AdminTools:        []string{},
				Interpreters:      []string{},
				Compilers:         []string{},
				PackageManagers:   []string{},
			},
			Risks:           nil,
			Recommendations: []string{fmt.Sprintf("Filesystem audit skipped: run 'sudo ./nspect --pid %d' to inspect container overlay filesystem.", pid)},
			Score:           100,
		}, nil
	}

	var risks []FilesystemRisk
	var recs []string
	scoreReduction := 0

	// 1. SUID/SGID Binary Scanner & Tooling Inventory in common directories
	binaryDirs := []string{
		"/bin",
		"/sbin",
		"/usr/bin",
		"/usr/sbin",
		"/usr/local/bin",
		"/usr/local/sbin",
	}

	knownShells := map[string]bool{"sh": true, "bash": true, "ash": true, "dash": true, "zsh": true, "ksh": true, "csh": true, "tcsh": true}
	knownDownloaders := map[string]bool{"curl": true, "wget": true, "nc": true, "netcat": true, "socat": true, "ncat": true, "tftp": true, "ftp": true, "scp": true, "sftp": true}
	knownAdmin := map[string]bool{"sudo": true, "su": true, "chroot": true, "mknod": true, "mount": true, "umount": true, "pivot_root": true, "unshare": true, "nsenter": true, "insmod": true, "modprobe": true, "rmmod": true, "lsmod": true, "iptables": true, "nft": true, "sysctl": true, "gpasswd": true, "newgrp": true, "passwd": true, "useradd": true, "usermod": true, "userdel": true, "groupadd": true, "kexec": true, "dmesg": true, "ptrace": true, "gdb": true, "strace": true, "tcpdump": true}
	knownInterpreters := map[string]bool{"python": true, "python2": true, "python3": true, "perl": true, "ruby": true, "php": true, "lua": true, "node": true, "nodejs": true, "deno": true, "bun": true}
	knownCompilers := map[string]bool{"gcc": true, "g++": true, "clang": true, "clang++": true, "make": true, "as": true, "ld": true, "cc": true, "rustc": true, "go": true}
	knownPkgMgrs := map[string]bool{"apt": true, "apt-get": true, "dpkg": true, "apk": true, "rpm": true, "yum": true, "dnf": true, "pacman": true, "zypper": true, "microdnf": true}

	var allBinaries []string
	var shells []string
	var downloaders []string
	var adminTools []string
	var interpreters []string
	var compilers []string
	var pkgManagers []string
	seenBinary := make(map[string]bool)

	foundSUID := 0
	for _, dir := range binaryDirs {
		targetDir := filepath.Join(rootPath, dir)
		if _, err := os.Stat(targetDir); err != nil {
			continue
		}

		entries, err := os.ReadDir(targetDir)
		if err != nil {
			continue
		}

		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}

			filePath := filepath.Join(targetDir, entry.Name())
			info, err := os.Lstat(filePath)
			if err != nil {
				continue
			}

			nameLower := strings.ToLower(entry.Name())
			if !seenBinary[nameLower] {
				seenBinary[nameLower] = true
				allBinaries = append(allBinaries, entry.Name())
				if knownShells[nameLower] {
					shells = append(shells, entry.Name())
				}
				if knownDownloaders[nameLower] {
					downloaders = append(downloaders, entry.Name())
				}
				if knownAdmin[nameLower] {
					adminTools = append(adminTools, entry.Name())
				}
				if knownInterpreters[nameLower] {
					interpreters = append(interpreters, entry.Name())
				}
				if knownCompilers[nameLower] {
					compilers = append(compilers, entry.Name())
				}
				if knownPkgMgrs[nameLower] {
					pkgManagers = append(pkgManagers, entry.Name())
				}
			}

			// Skip symlinks for SUID check
			if info.Mode()&os.ModeSymlink != 0 {
				continue
			}

			// Check for SUID or SGID bits
			mode := info.Mode()
			if mode&os.ModeSetuid != 0 || mode&os.ModeSetgid != 0 {
				containerPath := filepath.Join(dir, entry.Name())
				riskLvl := "Medium"
				desc := fmt.Sprintf("SUID/SGID binary found inside container: %s. If an attacker gains code execution as a non-root user inside the container, they can exploit vulnerability in this binary to escalate to container root.", containerPath)
				
				if nameLower == "sudo" || nameLower == "su" || nameLower == "chsh" || nameLower == "chfn" {
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
		CheckOthers bool
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

		if sf.CheckWrite && (mode&0002 != 0) {
			isVulnerable = true
			vulnDesc = append(vulnDesc, "world-writable (mode allows any user to modify)")
		}

		if sf.CheckOthers && (mode&0007 != 0) {
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

	// 3. Scan for common configuration files with secrets
	secretFilesPattern := []string{
		"/.env",
		"/app/.env",
		"/var/www/html/.env",
	}
	foundSecrets := 0
	for _, spf := range secretFilesPattern {
		targetFile := filepath.Join(rootPath, spf)
		if _, err := os.Stat(targetFile); err == nil {
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

	// 4. Distroless / Rock / Minimal Image Detection Heuristics
	hasShell := len(shells) > 0
	hasPkgMgr := len(pkgManagers) > 0
	hasPebble := seenBinary["pebble"]

	if !hasPebble {
		for _, pb := range []string{"/charm/bin/pebble", "/usr/bin/pebble", "/bin/pebble", "/var/lib/pebble"} {
			if _, err := os.Stat(filepath.Join(rootPath, pb)); err == nil {
				hasPebble = true
				break
			}
		}
	}

	isChiselled := false
	isDistroless := false
	osPrettyName := ""

	if osRelData, err := os.ReadFile(filepath.Join(rootPath, "/etc/os-release")); err == nil {
		contentLower := strings.ToLower(string(osRelData))
		for _, line := range strings.Split(string(osRelData), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "PRETTY_NAME=") {
				osPrettyName = strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), "\"")
			}
		}

		if (strings.Contains(contentLower, "chisel") || strings.Contains(contentLower, "rockcraft")) && !hasPkgMgr {
			isChiselled = true
		}
		if strings.Contains(contentLower, "distroless") && !hasPkgMgr {
			isDistroless = true
		}
	}

	if !hasShell && !hasPkgMgr {
		isDistroless = true
		if hasPebble {
			isChiselled = true
		}
	}

	flavor := "Standard Linux Distribution"
	if osPrettyName != "" {
		flavor = osPrettyName
	}

	if hasPebble {
		flavor = "Ubuntu Rock (Pebble Managed)"
	} else if isChiselled {
		flavor = "Ubuntu Chiselled / Minimal Image"
	} else if isDistroless {
		flavor = "Distroless Minimal Image"
	}

	finalScore := 100 - scoreReduction
	if finalScore < 0 {
		finalScore = 0
	}

	tooling := &ToolingInventory{
		TotalBinaries:     len(allBinaries),
		InstalledBinaries: allBinaries,
		Shells:            shells,
		Downloaders:       downloaders,
		AdminTools:        adminTools,
		Interpreters:      interpreters,
		Compilers:         compilers,
		PackageManagers:   pkgManagers,
	}

	return &FilesystemAuditResult{
		IsAccessible:     true,
		SUIDCount:        foundSUID,
		IsDistroless:     isDistroless,
		IsChiselled:      isChiselled,
		HasShell:         hasShell,
		HasPkgManager:    hasPkgMgr,
		ImageFlavor:      flavor,
		Tooling:          tooling,
		Risks:           risks,
		Recommendations: recs,
		Score:           finalScore,
	}, nil
}

