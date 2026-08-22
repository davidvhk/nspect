package auditor

import "fmt"

// BreakoutFeasibility represents a realistic exploit feasibility rating.
// Unlike raw severity scores, this accounts for what an attacker actually needs
// to execute an attack given the current capability and tooling context.
type BreakoutFeasibility string

const (
	FeasibilityNone     BreakoutFeasibility = "Not Feasible"
	FeasibilityLow      BreakoutFeasibility = "Low"
	FeasibilityModerate BreakoutFeasibility = "Moderate"
	FeasibilityHigh     BreakoutFeasibility = "High"
	FeasibilityTrivial  BreakoutFeasibility = "Trivial"
)

// BreakoutAssessment is the analysis of a single attack vector.
type BreakoutAssessment struct {
	Vector      string              `json:"vector"`
	Feasibility BreakoutFeasibility `json:"feasibility"`
	Explanation string              `json:"explanation"`
	Mitigations []string            `json:"mitigations"`
}

// BreakoutFeasibilityResult is the full cross-correlated breakout analysis.
type BreakoutFeasibilityResult struct {
	Assessments    []BreakoutAssessment `json:"assessments"`
	OverallVerdict BreakoutFeasibility  `json:"overall_verdict"`
}

type toolingContext struct {
	hasShell        bool
	hasAdminTools   bool
	hasNetTools     bool
	hasInterpreters bool
	rootfsWritable  bool
}

func buildToolingContext(fs *FilesystemAuditResult, mounts *MountAuditResult) toolingContext {
	ctx := toolingContext{}
	if fs != nil && fs.Tooling != nil {
		ctx.hasShell = len(fs.Tooling.Shells) > 0
		ctx.hasAdminTools = len(fs.Tooling.AdminTools) > 0
		ctx.hasNetTools = len(fs.Tooling.Downloaders) > 0
		ctx.hasInterpreters = len(fs.Tooling.Interpreters) > 0 || len(fs.Tooling.Compilers) > 0
	}
	if mounts != nil {
		for _, m := range mounts.Mounts {
			if m.MountPoint == "/" {
				if hasOption(m.MountOptions, "rw") || hasOption(m.SuperOptions, "rw") {
					ctx.rootfsWritable = true
				}
			}
		}
	}
	return ctx
}

// exploitDifficulty returns feasibility based on available tooling.
// requiredSyscallOnly: true when the exploit only needs a raw syscall (no userspace tool).
func exploitDifficulty(ctx toolingContext, requiredSyscallOnly bool, vectorName string) (BreakoutFeasibility, string) {
	if requiredSyscallOnly {
		return FeasibilityHigh, fmt.Sprintf(
			"%s exploit requires only a raw syscall — no shell or userspace tools needed. "+
				"Any RCE payload (memory corruption, deserialization, etc.) can trigger this directly.",
			vectorName,
		)
	}
	if ctx.hasShell && ctx.hasAdminTools {
		return FeasibilityTrivial, fmt.Sprintf(
			"%s: shell and admin tools present — exploit is a one-liner command.", vectorName,
		)
	}
	if ctx.hasShell {
		return FeasibilityHigh, fmt.Sprintf(
			"%s: shell present. Admin tools absent but shell alone is sufficient for many techniques.", vectorName,
		)
	}
	if ctx.hasInterpreters {
		return FeasibilityHigh, fmt.Sprintf(
			"%s: scripting interpreter present (python/perl/etc.) — can replace shell for exploitation.", vectorName,
		)
	}
	if ctx.hasNetTools && ctx.rootfsWritable {
		return FeasibilityModerate, fmt.Sprintf(
			"%s: no shell, but network downloader and writable rootfs present. "+
				"Attacker can download a pre-compiled exploit binary.", vectorName,
		)
	}
	if ctx.rootfsWritable {
		return FeasibilityModerate, fmt.Sprintf(
			"%s: no shell or network tools, but rootfs is writable. "+
				"Attacker must embed a custom binary in their RCE payload and drop it to disk.", vectorName,
		)
	}
	return FeasibilityLow, fmt.Sprintf(
		"%s: no shell, no tools, read-only rootfs. "+
			"Attacker must use a fully self-contained in-memory exploit. Difficult but not impossible.", vectorName,
	)
}

// AssessBreakoutFeasibility cross-correlates all audit results to produce
// a realistic per-vector breakout feasibility assessment.
func AssessBreakoutFeasibility(
	caps *CapabilityAuditResult,
	ns *NamespaceAuditResult,
	mounts *MountAuditResult,
	fs *FilesystemAuditResult,
) *BreakoutFeasibilityResult {

	var assessments []BreakoutAssessment
	ctx := buildToolingContext(fs, mounts)

	hasSysAdmin  := hasEffectiveCap(caps, "CAP_SYS_ADMIN")
	hasSysModule := hasEffectiveCap(caps, "CAP_SYS_MODULE")
	hasMknod     := hasEffectiveCap(caps, "CAP_MKNOD")
	hasSysPtrace := hasEffectiveCap(caps, "CAP_SYS_PTRACE")
	hasNetAdmin  := hasEffectiveCap(caps, "CAP_NET_ADMIN")
	hasNetRaw    := hasEffectiveCap(caps, "CAP_NET_RAW")
	hasSysRawIO  := hasEffectiveCap(caps, "CAP_SYS_RAWIO")

	// 1. Namespace sharing: visibility vs control
	sharedNS := []string{}
	if ns != nil {
		for _, n := range ns.Namespaces {
			if n.IsSharedWithHost {
				sharedNS = append(sharedNS, n.Name)
			}
		}
	}
	if len(sharedNS) > 0 {
		if !hasSysAdmin && !hasSysPtrace && !hasNetAdmin {
			assessments = append(assessments, BreakoutAssessment{
				Vector:      "Namespace Sharing (visibility only)",
				Feasibility: FeasibilityNone,
				Explanation: fmt.Sprintf(
					"%d namespace(s) shared with host (%v). Visibility without capability grants no control: "+
						"reading host /proc or network state is possible, but modifying kernel state requires "+
						"CAP_SYS_ADMIN, CAP_NET_ADMIN, or CAP_SYS_PTRACE — none are present. "+
						"Expected for monitoring tools like nspect running with --pid=host.",
					len(sharedNS), sharedNS,
				),
				Mitigations: []string{
					"Drop --pid=host if host-wide discovery is not needed.",
					"Grant only minimum required capabilities instead of --privileged.",
				},
			})
		} else {
			f, explanation := exploitDifficulty(ctx, false, "Shared namespace with control capabilities")
			assessments = append(assessments, BreakoutAssessment{
				Vector:      "Namespace Sharing + Control Capabilities",
				Feasibility: f,
				Explanation: explanation,
				Mitigations: []string{
					"Drop --pid=host to restore PID namespace isolation.",
					"Drop --privileged and use only the minimum required capabilities.",
				},
			})
		}
	}

	// 2. /proc core_pattern write (CAP_SYS_ADMIN only, no userspace tools needed)
	procWritable := false
	for _, r := range mounts.Risks {
		if r.MountPoint == "/proc" && (r.RiskLevel == "Critical" || r.RiskLevel == "High") {
			procWritable = true
		}
	}
	if hasSysAdmin && procWritable {
		f, explanation := exploitDifficulty(ctx, true, "/proc/sys/kernel/core_pattern write")
		assessments = append(assessments, BreakoutAssessment{
			Vector:      "/proc core_pattern escape (CAP_SYS_ADMIN + writable /proc)",
			Feasibility: f,
			Explanation: explanation,
			Mitigations: []string{
				"Drop CAP_SYS_ADMIN.",
				"Mount /proc read-only.",
				"Block write() to /proc/sys/kernel in seccomp profile.",
			},
		})
	}

	// 3. Shared mount propagation (CAP_SYS_ADMIN + mount syscall)
	hasSharedProp := false
	for _, m := range mounts.Mounts {
		for _, opt := range m.OptionalFields {
			if len(opt) >= 7 && opt[:7] == "shared:" {
				hasSharedProp = true
				break
			}
		}
	}
	if hasSysAdmin && hasSharedProp {
		f, explanation := exploitDifficulty(ctx, false, "Mount propagation escape")
		assessments = append(assessments, BreakoutAssessment{
			Vector:      "Shared Mount Propagation (CAP_SYS_ADMIN)",
			Feasibility: f,
			Explanation: explanation + " mount() syscall can propagate a bind mount to the host filesystem.",
			Mitigations: []string{
				"Drop CAP_SYS_ADMIN.",
				"Use '--mount type=bind,bind-propagation=slave' to change propagation to slave.",
				"Block mount() and unshare() in seccomp profile.",
			},
		})
	}

	// 4. /dev device node creation (CAP_MKNOD or CAP_SYS_ADMIN + writable /dev)
	devWritable := false
	for _, r := range mounts.Risks {
		if (r.MountPoint == "/dev" || r.FSType == "devtmpfs") && (r.RiskLevel == "High" || r.RiskLevel == "Critical") {
			devWritable = true
		}
	}
	if (hasMknod || hasSysAdmin) && devWritable {
		f, explanation := exploitDifficulty(ctx, false, "/dev device node escape")
		assessments = append(assessments, BreakoutAssessment{
			Vector:      "Raw Device Node Creation (CAP_MKNOD + writable /dev)",
			Feasibility: f,
			Explanation: explanation + " mknod() can create a raw block device node (e.g. /dev/sda) to read/write host storage.",
			Mitigations: []string{
				"Drop CAP_MKNOD and CAP_SYS_ADMIN.",
				"Mount /dev with 'nodev' option.",
				"Block mknod() in seccomp profile.",
			},
		})
	}

	// 5. Kernel module loading (CAP_SYS_MODULE — syscall only, no shell needed)
	if hasSysModule {
		f, explanation := exploitDifficulty(ctx, true, "Kernel module (LKM) rootkit")
		assessments = append(assessments, BreakoutAssessment{
			Vector:      "Kernel Module Loading (CAP_SYS_MODULE)",
			Feasibility: f,
			Explanation: explanation + " init_module() loads arbitrary code into kernel space, bypassing all isolation.",
			Mitigations: []string{
				"Drop CAP_SYS_MODULE.",
				"Block init_module() and finit_module() in seccomp profile.",
				"Enable kernel lockdown mode.",
			},
		})
	}

	// 6. CAP_SYS_RAWIO (direct memory/IO — syscall only)
	if hasSysRawIO {
		f, explanation := exploitDifficulty(ctx, true, "Direct memory/IO access")
		assessments = append(assessments, BreakoutAssessment{
			Vector:      "Direct Host Memory Access (CAP_SYS_RAWIO)",
			Feasibility: f,
			Explanation: explanation + " ioperm()/iopl() or /dev/mem access allows reading/writing host physical memory.",
			Mitigations: []string{
				"Drop CAP_SYS_RAWIO.",
				"Ensure /dev/mem is not accessible inside the container.",
			},
		})
	}

	// 7. CAP_SYS_PTRACE + shared PID namespace = process injection
	pidShared := false
	if ns != nil {
		for _, n := range ns.Namespaces {
			if n.Name == "pid" && n.IsSharedWithHost {
				pidShared = true
			}
		}
	}
	if hasSysPtrace && pidShared {
		f, explanation := exploitDifficulty(ctx, true, "ptrace host process injection")
		assessments = append(assessments, BreakoutAssessment{
			Vector:      "Process Injection via ptrace (CAP_SYS_PTRACE + shared PID namespace)",
			Feasibility: f,
			Explanation: explanation + " ptrace() can attach to any host process, read its memory, and inject shellcode.",
			Mitigations: []string{
				"Drop CAP_SYS_PTRACE.",
				"Drop --pid=host to isolate the PID namespace.",
				"Set kernel.yama.ptrace_scope >= 1 on the host.",
			},
		})
	}

	// 8. Network manipulation (CAP_NET_ADMIN/RAW + shared net namespace)
	netShared := false
	if ns != nil {
		for _, n := range ns.Namespaces {
			if n.Name == "net" && n.IsSharedWithHost {
				netShared = true
			}
		}
	}
	if (hasNetAdmin || hasNetRaw) && netShared {
		f, explanation := exploitDifficulty(ctx, false, "Host network manipulation")
		assessments = append(assessments, BreakoutAssessment{
			Vector:      "Host Network Manipulation (CAP_NET_ADMIN/RAW + shared network namespace)",
			Feasibility: f,
			Explanation: explanation + " Can modify host routing, firewall rules (iptables/nftables), or sniff all host traffic.",
			Mitigations: []string{
				"Drop CAP_NET_ADMIN and CAP_NET_RAW.",
				"Remove --network=host to restore network namespace isolation.",
			},
		})
	}

	// No findings
	if len(assessments) == 0 {
		assessments = append(assessments, BreakoutAssessment{
			Vector:      "No viable breakout vectors identified",
			Feasibility: FeasibilityNone,
			Explanation: "No combination of dangerous capabilities, mount misconfigurations, or namespace sharing that would enable host escape was detected.",
			Mitigations: []string{},
		})
	}

	// Overall verdict = worst case
	order := map[BreakoutFeasibility]int{
		FeasibilityNone:     0,
		FeasibilityLow:      1,
		FeasibilityModerate: 2,
		FeasibilityHigh:     3,
		FeasibilityTrivial:  4,
	}
	verdict := FeasibilityNone
	for _, a := range assessments {
		if order[a.Feasibility] > order[verdict] {
			verdict = a.Feasibility
		}
	}

	return &BreakoutFeasibilityResult{
		Assessments:    assessments,
		OverallVerdict: verdict,
	}
}
