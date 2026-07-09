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
	MountID        int      `json:"mount_id"`
	ParentID       int      `json:"parent_id"`
	MajorMinor     string   `json:"major_minor"`
	Root           string   `json:"root"`
	MountPoint     string   `json:"mount_point"`
	MountOptions   []string `json:"mount_options"`
	OptionalFields []string `json:"optional_fields"`
	FSType         string   `json:"fs_type"`
	MountSource    string   `json:"mount_source"`
	SuperOptions   []string `json:"super_options"`
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
	Mounts          []MountInfo `json:"mounts"`
	Risks           []MountRisk `json:"risks"`
	Recommendations []string    `json:"recommendations"`
	Score           int         `json:"score"` // 0 to 100
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

	var optionalFields []string
	if sepIndex > 6 {
		optionalFields = fields[6:sepIndex]
	}

	return &MountInfo{
		MountID:        mountID,
		ParentID:       parentID,
		MajorMinor:     majorMinor,
		Root:           root,
		MountPoint:     mountPoint,
		MountOptions:   mountOptions,
		OptionalFields: optionalFields,
		FSType:         fsType,
		MountSource:    mountSource,
		SuperOptions:   superOptions,
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

func isKernelPseudoFS(fsType string) bool {
	pseudoFS := map[string]bool{
		"proc":        true,
		"sysfs":       true,
		"devtmpfs":    true,
		"devpts":      true,
		"cgroup":      true,
		"cgroup2":     true,
		"pstore":      true,
		"securityfs":  true,
		"configfs":    true,
		"autofs":      true,
		"debugfs":     true,
		"tracefs":     true,
		"hugetlbfs":   true,
		"mqueue":      true,
		"selinuxfs":   true,
		"binfmt_misc": true,
		"nsfs":        true,
	}
	return pseudoFS[fsType]
}

// AuditMounts audits the mount configuration of a given process.
func AuditMounts(pid int) (*MountAuditResult, error) {
	mounts, err := ReadMountInfo(pid)
	if err != nil {
		return nil, fmt.Errorf("failed to read mountinfo: %w", err)
	}

	// Read LSM profile to check if it restricts writes to /sys and /proc paths
	lsmProfile := "none"
	lsmPath := util.ProcPath(pid, "attr", "current")
	lsmData, err := os.ReadFile(lsmPath)
	if err == nil {
		profile := strings.TrimSpace(string(lsmData))
		if profile != "" {
			lsmProfile = profile
		}
	}

	return auditMountsInternal(mounts, lsmProfile), nil
}

func auditMountsInternal(mounts []MountInfo, lsmProfile string) *MountAuditResult {
	lsmRestrictsWrites := false
	if lsmProfile != "none" && lsmProfile != "unconfined" && !strings.Contains(lsmProfile, "unconfined") && !strings.Contains(lsmProfile, "(complain)") {
		// AppArmor / SELinux active and enforcing
		if !strings.Contains(lsmProfile, "spc_t") {
			lsmRestrictsWrites = true
		}
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
				// Writable /proc is extremely dangerous unless protected by LSM
				if lsmRestrictsWrites {
					risks = append(risks, MountRisk{
						MountPoint:  m.MountPoint,
						MountSource: m.MountSource,
						FSType:      m.FSType,
						RiskLevel:   "Info",
						Description: fmt.Sprintf("Writable /proc filesystem mount detected, but write access is restricted by the active LSM profile (%s), preventing security exposure.", lsmProfile),
					})
				} else {
					risks = append(risks, MountRisk{
						MountPoint:  m.MountPoint,
						MountSource: m.MountSource,
						FSType:      m.FSType,
						RiskLevel:   "Critical",
						Description: "Writable /proc filesystem. Allows altering kernel parameters, sysctl values, or modifying core_pattern to trigger host commands upon crashes.",
					})
					scoreReduction += 35
				}
			} else if m.MountPoint == "/sys" || strings.HasPrefix(m.MountPoint, "/sys/") {
				// Writable /sys is extremely dangerous unless protected by LSM
				if lsmRestrictsWrites {
					risks = append(risks, MountRisk{
						MountPoint:  m.MountPoint,
						MountSource: m.MountSource,
						FSType:      m.FSType,
						RiskLevel:   "Info",
						Description: fmt.Sprintf("Writable /sys filesystem mount detected, but write access is restricted by the active LSM profile (%s), preventing security exposure.", lsmProfile),
					})
				} else {
					risks = append(risks, MountRisk{
						MountPoint:  m.MountPoint,
						MountSource: m.MountSource,
						FSType:      m.FSType,
						RiskLevel:   "Critical",
						Description: "Writable /sys filesystem. Allows direct manipulation of kernel interfaces, cgroup configs, device configurations, or loading modules/drivers.",
					})
					scoreReduction += 35
				}
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
			if !hasOption(m.MountOptions, "nosymfollow") {
				missingFlags = append(missingFlags, "nosymfollow")
			}

			if len(missingFlags) > 0 {
				risks = append(risks, MountRisk{
					MountPoint:  m.MountPoint,
					MountSource: m.MountSource,
					FSType:      m.FSType,
					RiskLevel:   "Low",
					Description: fmt.Sprintf("Writable directory %s is missing hardening flags: %s. An attacker can write and execute files, construct SUID payloads, create device nodes, or exploit symlinks here.", m.MountPoint, strings.Join(missingFlags, ", ")),
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

		// 5. General Mount Hardening Flags on external/bind/network/tmpfs mounts
		if isRW && m.MountPoint != "/" && !isKernelPseudoFS(m.FSType) &&
			m.MountPoint != "/tmp" && m.MountPoint != "/dev/shm" && m.MountPoint != "/run/lock" {
			
			if !hasOption(m.MountOptions, "nosuid") && !hasOption(m.SuperOptions, "nosuid") {
				risks = append(risks, MountRisk{
					MountPoint:  m.MountPoint,
					MountSource: m.MountSource,
					FSType:      m.FSType,
					RiskLevel:   "High",
					Description: fmt.Sprintf("Writable volume/bind mount %s is missing the 'nosuid' flag. An attacker can write SUID binaries to this volume, which can be executed (e.g., on the host or other namespaces) to escalate privileges.", m.MountPoint),
				})
				scoreReduction += 15
			}
			if !hasOption(m.MountOptions, "nodev") && !hasOption(m.SuperOptions, "nodev") {
				risks = append(risks, MountRisk{
					MountPoint:  m.MountPoint,
					MountSource: m.MountSource,
					FSType:      m.FSType,
					RiskLevel:   "High",
					Description: fmt.Sprintf("Writable volume/bind mount %s is missing the 'nodev' flag. An attacker with CAP_MKNOD capability can create device nodes on this filesystem to access host hardware directly.", m.MountPoint),
				})
				scoreReduction += 15
			}
			if !hasOption(m.MountOptions, "noexec") && !hasOption(m.SuperOptions, "noexec") {
				risks = append(risks, MountRisk{
					MountPoint:  m.MountPoint,
					MountSource: m.MountSource,
					FSType:      m.FSType,
					RiskLevel:   "Medium",
					Description: fmt.Sprintf("Writable volume/bind mount %s is missing the 'noexec' flag. This allows execution of binaries directly from the volume, facilitating the execution of compiled payloads.", m.MountPoint),
				})
				scoreReduction += 10
			}
			if !hasOption(m.MountOptions, "nosymfollow") && !hasOption(m.SuperOptions, "nosymfollow") {
				risks = append(risks, MountRisk{
					MountPoint:  m.MountPoint,
					MountSource: m.MountSource,
					FSType:      m.FSType,
					RiskLevel:   "Medium",
					Description: fmt.Sprintf("Writable volume/bind mount %s is missing the 'nosymfollow' flag. An attacker can create symbolic links pointing to sensitive host files, which could lead to a symlink-following host escape if accessed by a privileged host process.", m.MountPoint),
				})
				scoreReduction += 10
			}
		}

		// 6. NFS Mount Security Audits
		isNFS := strings.HasPrefix(m.FSType, "nfs")
		if isNFS {
			// Check for sec=sys or lack of sec=krb5/krb5i/krb5p
			hasKrb := false
			hasSecSys := false
			for _, opt := range m.MountOptions {
				if strings.HasPrefix(opt, "sec=krb5") {
					hasKrb = true
				}
				if opt == "sec=sys" {
					hasSecSys = true
				}
			}
			for _, opt := range m.SuperOptions {
				if strings.HasPrefix(opt, "sec=krb5") {
					hasKrb = true
				}
				if opt == "sec=sys" {
					hasSecSys = true
				}
			}

			if !hasKrb || hasSecSys {
				risks = append(risks, MountRisk{
					MountPoint:  m.MountPoint,
					MountSource: m.MountSource,
					FSType:      m.FSType,
					RiskLevel:   "Medium",
					Description: fmt.Sprintf("NFS mount %s uses weak 'sec=sys' authentication (or defaults to it). It relies on the client system to assert UIDs/GIDs over the network without cryptographic verification, allowing identity spoofing.", m.MountPoint),
				})
				scoreReduction += 10
			}

			// Check for noresvport
			if hasOption(m.MountOptions, "noresvport") || hasOption(m.SuperOptions, "noresvport") {
				risks = append(risks, MountRisk{
					MountPoint:  m.MountPoint,
					MountSource: m.MountSource,
					FSType:      m.FSType,
					RiskLevel:   "Medium",
					Description: fmt.Sprintf("NFS mount %s is configured with 'noresvport'. This allows the NFS client to use unprivileged source ports (>1024), bypassing source port security checks on the NFS server.", m.MountPoint),
				})
				scoreReduction += 5
			}

			// Check for UDP protocol
			hasUDP := hasOption(m.MountOptions, "proto=udp") || hasOption(m.SuperOptions, "proto=udp") ||
				hasOption(m.MountOptions, "udp") || hasOption(m.SuperOptions, "udp")
			if hasUDP {
				risks = append(risks, MountRisk{
					MountPoint:  m.MountPoint,
					MountSource: m.MountSource,
					FSType:      m.FSType,
					RiskLevel:   "Low",
					Description: fmt.Sprintf("NFS mount %s uses UDP transport protocol. UDP is stateless and susceptible to source IP spoofing and session hijacking compared to TCP.", m.MountPoint),
				})
				scoreReduction += 3
			}

			// Check for NFSv3 or earlier
			isNFSv3OrEarlier := m.FSType == "nfs" || hasOption(m.MountOptions, "vers=3") || hasOption(m.SuperOptions, "vers=3") ||
				hasOption(m.MountOptions, "vers=2") || hasOption(m.SuperOptions, "vers=2") ||
				hasOption(m.MountOptions, "v3") || hasOption(m.SuperOptions, "v3") ||
				hasOption(m.MountOptions, "v2") || hasOption(m.SuperOptions, "v2")
			if isNFSv3OrEarlier {
				risks = append(risks, MountRisk{
					MountPoint:  m.MountPoint,
					MountSource: m.MountSource,
					FSType:      m.FSType,
					RiskLevel:   "Low",
					Description: fmt.Sprintf("NFS mount %s uses NFSv3 (or earlier). NFSv3 lacks modern security features of NFSv4, such as strong state tracking, integrated ACLs, and single-port operation.", m.MountPoint),
				})
				scoreReduction += 3
			}
		}

		// Check for Shared Mount Propagation
		hasSharedPropagation := false
		for _, opt := range m.OptionalFields {
			if strings.HasPrefix(opt, "shared:") {
				hasSharedPropagation = true
				break
			}
		}
		if hasSharedPropagation && isRW {
			risks = append(risks, MountRisk{
				MountPoint:  m.MountPoint,
				MountSource: m.MountSource,
				FSType:      m.FSType,
				RiskLevel:   "High",
				Description: fmt.Sprintf("Mount %s is configured with shared propagation ('shared:'). Any mount or unmount event inside the namespace will propagate back to the host, posing a container escape or denial-of-service vector.", m.MountPoint),
			})
			scoreReduction += 20
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

	// Collect recommendations
	var recs []string
	hasMissingNosuid := false
	hasMissingNodev := false
	hasMissingNoexec := false
	hasMissingNosymfollow := false
	hasNfsWeakSec := false
	hasNfsNoResvPort := false
	hasNfsUdp := false
	hasNfsV3 := false

	for _, r := range risks {
		if strings.Contains(r.Description, "nosuid") {
			hasMissingNosuid = true
		}
		if strings.Contains(r.Description, "nodev") {
			hasMissingNodev = true
		}
		if strings.Contains(r.Description, "noexec") {
			hasMissingNoexec = true
		}
		if strings.Contains(r.Description, "nosymfollow") {
			hasMissingNosymfollow = true
		}
		if strings.Contains(r.Description, "sec=sys") {
			hasNfsWeakSec = true
		}
		if strings.Contains(r.Description, "noresvport") {
			hasNfsNoResvPort = true
		}
		if strings.Contains(r.Description, "UDP transport") {
			hasNfsUdp = true
		}
		if strings.Contains(r.Description, "NFSv3") {
			hasNfsV3 = true
		}
	}

	hasSharedPropagation := false
	for _, r := range risks {
		if strings.Contains(r.Description, "shared propagation") {
			hasSharedPropagation = true
		}
	}

	hasNestedContainers := false
	for _, m := range mounts {
		ptL := strings.ToLower(m.MountPoint)
		if strings.Contains(ptL, "docker") || strings.Contains(ptL, "containerd") || m.FSType == "overlay" {
			hasNestedContainers = true
			break
		}
	}

	if hasMissingNosuid {
		recs = append(recs, "Mount critical volumes (especially host-bind mounts or shared directories) with the 'nosuid' option to prevent privilege escalation via SUID binaries.")
	}
	if hasMissingNodev {
		recs = append(recs, "Mount external/shared directories with the 'nodev' option to prevent container processes from creating or accessing raw block/character devices.")
	}
	if hasMissingNoexec {
		recs = append(recs, "Ensure writable filesystems not hosting executable programs are mounted with the 'noexec' option to block execution of dropped binaries/payloads.")
	}
	if hasMissingNosymfollow {
		recs = append(recs, "Mount user-writable directories or shared host paths with the 'nosymfollow' option to prevent symlink-following host escape vulnerabilities.")
	}
	if hasSharedPropagation {
		recs = append(recs, "Configure mount propagation to 'slave' or 'private' (e.g. using '--mount type=bind,src=...,dst=...,bind-propagation=slave' in Docker) to prevent container filesystem operations from propagating to the host.")
	}
	if hasNestedContainers {
		recs = append(recs, "Nested container workloads detected (Docker/OverlayFS). Ensure nested containers drop CAP_MKNOD and CAP_NET_RAW, and run with '--security-opt=no-new-privileges' to block nested breakouts.")
		recs = append(recs, "For nested Docker/LXC mount paths, configure mount options with 'nodev,nosuid,noexec' to prevent container filesystem breakouts.")
	}
	if hasNfsWeakSec {
		recs = append(recs, "Configure NFS mounts to use Kerberos authentication (e.g., 'sec=krb5', 'sec=krb5i', or 'sec=krb5p') instead of UNIX UID/GID mapping ('sec=sys') to prevent identity spoofing.")
	}
	if hasNfsNoResvPort {
		recs = append(recs, "Avoid using 'noresvport' on NFS client mounts unless required, as it permits connections from unprivileged client source ports, bypassing standard export restrictions.")
	}
	if hasNfsUdp {
		recs = append(recs, "Use TCP transport ('proto=tcp') instead of UDP ('proto=udp') for NFS mounts to ensure packet delivery reliability and resist spoofing/hijacking.")
	}
	if hasNfsV3 {
		recs = append(recs, "Upgrade NFS client mounts to use NFSv4 (e.g., 'vers=4') to benefit from modern security features like strong state tracking and integrated ACLs.")
	}

	return &MountAuditResult{
		Mounts:          mounts,
		Risks:           risks,
		Recommendations: recs,
		Score:           finalScore,
	}
}
