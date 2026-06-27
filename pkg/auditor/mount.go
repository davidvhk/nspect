package auditor

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"nspect/pkg/util"
)

// MountInfo represents a parsed mount entry from /proc/[pid]/mountinfo.
type MountInfo struct {
	MountID      int      `json:"mount_id"`
	ParentID     int      `json:"parent_id"`
	MajorMinor   string   `json:"major_minor"`
	Root         string   `json:"root"`
	MountPoint   string   `json:"mount_point"`
	MountOptions []string `json:"mount_options"`
	FSType       string   `json:"fs_type"`
	MountSource  string   `json:"mount_source"`
	SuperOptions []string `json:"super_options"`
}

// MountRisk details a discovered mount security exposure.
type MountRisk struct {
	MountPoint  string `json:"mount_point"`
	MountSource string `json:"mount_source"`
	FSType      string `json:"fs_type"`
	RiskLevel   string `json:"risk_level"` // Critical, High, Medium, Low
	Description string `json:"description"`
}

// MountAuditResult aggregates all mount assessments.
type MountAuditResult struct {
	Mounts []MountInfo `json:"mounts"`
	Risks  []MountRisk `json:"risks"`
	Score  int         `json:"score"` // 0 to 100
}

// ParseMountInfoLine decodes a single line from /proc/[pid]/mountinfo.
func ParseMountInfoLine(line string) (*MountInfo, error) {
	fields := strings.Fields(line)
	if len(fields) < 10 {
		return nil, fmt.Errorf("invalid mountinfo line: too few fields (%d)", len(fields))
	}

	mountID, err := strconv.Atoi(fields[0])
	if err != nil {
		return nil, fmt.Errorf("failed to parse mount ID: %w", err)
	}

	parentID, err := strconv.Atoi(fields[1])
	if err != nil {
		return nil, fmt.Errorf("failed to parse parent ID: %w", err)
	}

	majorMinor := fields[2]
	root := fields[3]
	mountPoint := fields[4]
	mountOptions := strings.Split(fields[5], ",")

	// Find the separator "-"
	sepIndex := -1
	for i := 6; i < len(fields); i++ {
		if fields[i] == "-" {
			sepIndex = i
			break
		}
	}

	if sepIndex == -1 || sepIndex+2 >= len(fields) {
		return nil, fmt.Errorf("invalid mountinfo line: missing separator or trailing fields")
	}

	fsType := fields[sepIndex+1]
	mountSource := fields[sepIndex+2]

	var superOptions []string
	if sepIndex+3 < len(fields) {
		superOptions = strings.Split(fields[sepIndex+3], ",")
	}

	return &MountInfo{
		MountID:      mountID,
		ParentID:     parentID,
		MajorMinor:   majorMinor,
		Root:         root,
		MountPoint:   mountPoint,
		MountOptions: mountOptions,
		FSType:       fsType,
		MountSource:  mountSource,
		SuperOptions: superOptions,
	}, nil
}

// ReadMountInfo parses the /proc/[pid]/mountinfo file.
func ReadMountInfo(pid int) ([]MountInfo, error) {
	file, err := os.Open(util.ProcPath(pid, "mountinfo"))
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var mounts []MountInfo
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		mInfo, err := ParseMountInfoLine(line)
		if err != nil {
			// Skip malformed lines instead of failing completely, but log internally if needed
			continue
		}
		mounts = append(mounts, *mInfo)
	}

	return mounts, scanner.Err()
}

// hasOption checks if an option exists in options list.
func hasOption(opts []string, opt string) bool {
	for _, o := range opts {
		if o == opt {
			return true
		}
	}
	return false
}

// AuditMounts audits the mount configuration of a given process.
func AuditMounts(pid int) (*MountAuditResult, error) {
	mounts, err := ReadMountInfo(pid)
	if err != nil {
		return nil, fmt.Errorf("failed to read mountinfo: %w", err)
	}

	var risks []MountRisk
	scoreReduction := 0

	for _, m := range mounts {
		isRW := hasOption(m.MountOptions, "rw") || hasOption(m.SuperOptions, "rw")

		// 1. Docker/Container Socket Exposure
		srcLower := strings.ToLower(m.MountSource)
		pointLower := strings.ToLower(m.MountPoint)
		if strings.Contains(srcLower, "docker.sock") || strings.Contains(pointLower, "docker.sock") {
			risks = append(risks, MountRisk{
				MountPoint:  m.MountPoint,
				MountSource: m.MountSource,
				FSType:      m.FSType,
				RiskLevel:   "Critical",
				Description: "Docker daemon socket is exposed. A container can use this socket to run commands on the host daemon, leading directly to host root takeover.",
			})
			scoreReduction += 40
		} else if strings.Contains(srcLower, "containerd.sock") || strings.Contains(pointLower, "containerd.sock") ||
			strings.Contains(srcLower, "podman.sock") || strings.Contains(pointLower, "podman.sock") ||
			strings.Contains(srcLower, "lxd.sock") || strings.Contains(pointLower, "lxd.sock") {
			risks = append(risks, MountRisk{
				MountPoint:  m.MountPoint,
				MountSource: m.MountSource,
				FSType:      m.FSType,
				RiskLevel:   "Critical",
				Description: "Container runtime control socket is exposed, allowing direct container bypass and host escape.",
			})
			scoreReduction += 40
		}

		// 2. Sensitive paths (procfs, sysfs, hosts/devs)
		if isRW {
			if m.MountPoint == "/proc" || strings.HasPrefix(m.MountPoint, "/proc/") {
				// Writable /proc is extremely dangerous
				// Check if it's a specific subpath that is ok, but generally proc should be read-only or masked
				risks = append(risks, MountRisk{
					MountPoint:  m.MountPoint,
					MountSource: m.MountSource,
					FSType:      m.FSType,
					RiskLevel:   "Critical",
					Description: "Writable /proc filesystem. Allows altering kernel parameters, sysctl values, or modifying core_pattern to trigger host commands upon crashes.",
				})
				scoreReduction += 35
			} else if m.MountPoint == "/sys" || strings.HasPrefix(m.MountPoint, "/sys/") {
				// Writable /sys
				risks = append(risks, MountRisk{
					MountPoint:  m.MountPoint,
					MountSource: m.MountSource,
					FSType:      m.FSType,
					RiskLevel:   "Critical",
					Description: "Writable /sys filesystem. Allows direct manipulation of kernel interfaces, cgroup configs, device configurations, or loading modules/drivers.",
				})
				scoreReduction += 35
			} else if m.MountPoint == "/dev" || m.FSType == "devtmpfs" {
				risks = append(risks, MountRisk{
					MountPoint:  m.MountPoint,
					MountSource: m.MountSource,
					FSType:      m.FSType,
					RiskLevel:   "High",
					Description: "Writable /dev or devtmpfs. Allows processes (with CAP_MKNOD or raw device write) to create raw physical drive nodes (e.g. sda) and read/write host filesystems directly.",
				})
				scoreReduction += 30
			} else if strings.HasPrefix(m.MountPoint, "/lib/modules") || strings.Contains(srcLower, "/lib/modules") {
				risks = append(risks, MountRisk{
					MountPoint:  m.MountPoint,
					MountSource: m.MountSource,
					FSType:      m.FSType,
					RiskLevel:   "Critical",
					Description: "Writable /lib/modules host path is exposed. Enables replacing host kernel modules, allowing execution of code directly in host kernel context.",
				})
				scoreReduction += 35
			} else if m.MountPoint == "/" {
				// Standard containers have writable root, but hardened ones might set read-only root.
				// We classify this as Low or Info. Let's make it Info/Low since it's normal but good to note.
				risks = append(risks, MountRisk{
					MountPoint:  m.MountPoint,
					MountSource: m.MountSource,
					FSType:      m.FSType,
					RiskLevel:   "Low",
					Description: "Root filesystem is mounted read-write. Hardened containers should utilize a read-only root filesystem with ephemeral tmpfs volumes where writing is needed.",
				})
				scoreReduction += 5
			}
		}

		// 3. Check for lack of security flags on writeable tmpfs / scratch spaces
		if isRW && (m.MountPoint == "/tmp" || m.MountPoint == "/dev/shm" || m.MountPoint == "/run/lock") {
			var missingFlags []string
			if !hasOption(m.MountOptions, "noexec") {
				missingFlags = append(missingFlags, "noexec")
			}
			if !hasOption(m.MountOptions, "nosuid") {
				missingFlags = append(missingFlags, "nosuid")
			}
			if !hasOption(m.MountOptions, "nodev") {
				missingFlags = append(missingFlags, "nodev")
			}

			if len(missingFlags) > 0 {
				risks = append(risks, MountRisk{
					MountPoint:  m.MountPoint,
					MountSource: m.MountSource,
					FSType:      m.FSType,
					RiskLevel:   "Low",
					Description: fmt.Sprintf("Writable directory %s is missing hardening flags: %s. An attacker can write and execute files or construct SUID payloads here.", m.MountPoint, strings.Join(missingFlags, ", ")),
				})
				scoreReduction += 3 * len(missingFlags)
			}
		}

		// 4. Exposed Host Root Directories (e.g. mounting host / to /host or similar)
		// We can detect this by checking if MountSource starts with a disk block device and MountPoint is not /
		// or if MountPoint is typical host mount like /host, /hostroot, /mnt/host etc.
		if isRW && (m.MountPoint == "/host" || strings.HasPrefix(m.MountPoint, "/host/") ||
			m.MountPoint == "/hostroot" || strings.HasPrefix(m.MountPoint, "/hostroot/")) {
			risks = append(risks, MountRisk{
				MountPoint:  m.MountPoint,
				MountSource: m.MountSource,
				FSType:      m.FSType,
				RiskLevel:   "High",
				Description: "Exposed writeable host root directory. Gives direct access to the host's filesystem, bypassing all file isolation.",
			})
			scoreReduction += 30
		}
	}

	// Calculate score
	finalScore := 100 - scoreReduction
	if finalScore < 0 {
		finalScore = 0
	}

	// If root filesystem is mounted read-only and no high-risk mounts are present, it's a very good sign.
	isRootRO := false
	for _, m := range mounts {
		if m.MountPoint == "/" && (hasOption(m.MountOptions, "ro") || hasOption(m.SuperOptions, "ro")) {
			isRootRO = true
			break
		}
	}
	if isRootRO && len(risks) == 0 {
		finalScore = 100 // Read-only root and no issues is a perfect score
	}

	return &MountAuditResult{
		Mounts: mounts,
		Risks:  risks,
		Score:  finalScore,
	}, nil
}
