package auditor

import (
	"testing"
)

func TestBreakoutFeasibility_UnprivilegedRock(t *testing.T) {
	caps := &CapabilityAuditResult{
		Sets: CapabilitySet{
			Effective: []string{}, // Zero caps
		},
		Score: 100,
	}
	ns := &NamespaceAuditResult{
		Namespaces: []NamespaceInfo{
			{Name: "cgroup", IsSharedWithHost: true},
			{Name: "ipc", IsSharedWithHost: true},
			{Name: "mnt", IsSharedWithHost: true},
			{Name: "net", IsSharedWithHost: true},
			{Name: "pid", IsSharedWithHost: true},
			{Name: "user", IsSharedWithHost: true},
			{Name: "uts", IsSharedWithHost: true},
		},
		Score: 0,
	}
	mounts := &MountAuditResult{
		Mounts: []MountInfo{
			{MountPoint: "/", MountOptions: []string{"rw"}},
			{MountPoint: "/proc", MountOptions: []string{"rw"}},
			{MountPoint: "/sys", MountOptions: []string{"rw"}},
		},
		Risks: []MountRisk{
			{MountPoint: "/proc", RiskLevel: "Low"},
			{MountPoint: "/sys", RiskLevel: "Low"},
		},
		Score: 74,
	}
	fs := &FilesystemAuditResult{
		Tooling: &ToolingInventory{
			TotalBinaries:     2,
			InstalledBinaries: []string{"/usr/bin/nspect", "/usr/bin/pebble"},
			Shells:            []string{},
			Downloaders:       []string{},
			AdminTools:        []string{},
			Interpreters:      []string{},
		},
	}

	result := AssessBreakoutFeasibility(caps, ns, mounts, fs)
	if result == nil {
		t.Fatalf("expected non-nil result")
	}

	if result.OverallVerdict != FeasibilityNone {
		t.Errorf("expected OverallVerdict %v, got %v", FeasibilityNone, result.OverallVerdict)
	}

	if len(result.Assessments) == 0 {
		t.Errorf("expected assessments, got 0")
	}
}

func TestBreakoutFeasibility_PrivilegedProcess(t *testing.T) {
	caps := &CapabilityAuditResult{
		Sets: CapabilitySet{
			Effective: []string{"CAP_SYS_ADMIN", "CAP_SYS_PTRACE", "CAP_SYS_MODULE"},
		},
		Score: 0,
	}
	ns := &NamespaceAuditResult{
		Namespaces: []NamespaceInfo{
			{Name: "pid", IsSharedWithHost: true},
		},
		Score: 50,
	}
	mounts := &MountAuditResult{
		Mounts: []MountInfo{
			{MountPoint: "/", MountOptions: []string{"rw"}},
			{MountPoint: "/proc", MountOptions: []string{"rw"}},
		},
		Risks: []MountRisk{
			{MountPoint: "/proc", RiskLevel: "Critical"},
		},
		Score: 20,
	}
	fs := &FilesystemAuditResult{
		Tooling: &ToolingInventory{
			TotalBinaries:     50,
			InstalledBinaries: []string{"/bin/bash", "/bin/mount"},
			Shells:            []string{"/bin/bash"},
			AdminTools:        []string{"/bin/mount"},
		},
	}

	result := AssessBreakoutFeasibility(caps, ns, mounts, fs)
	if result == nil {
		t.Fatalf("expected non-nil result")
	}

	if result.OverallVerdict != FeasibilityHigh && result.OverallVerdict != FeasibilityTrivial {
		t.Errorf("expected OverallVerdict High or Trivial, got %v", result.OverallVerdict)
	}
}
