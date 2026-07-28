package auditor

import (
	"testing"
)

func TestEvaluateCVEs(t *testing.T) {
	// Test report with host FD leak and CAP_SYS_ADMIN
	report := &AuditReport{
		PID:         123,
		ProcessName: "test_process",
		FD: &FDAuditResult{
			FDs: []FDInfo{
				{
					FD:         3,
					Type:       "Directory",
					Target: "/var/lib/docker",
					IsHighRisk: true,
				},
			},
		},
		Capabilities: &CapabilityAuditResult{
			Sets: CapabilitySet{
				Effective: []string{"CAP_SYS_ADMIN", "CAP_BPF"},
			},
		},
		Mounts: &MountAuditResult{
			Risks: []MountRisk{
				{
					MountPoint: "/sys/fs/cgroup",
					RiskLevel:  "Critical",
				},
			},
		},
	}

	findings := EvaluateCVEs(report)
	if len(findings) == 0 {
		t.Fatalf("Expected CVE findings for process with FD leak and CAP_SYS_ADMIN, got 0")
	}

	foundLeakyVessels := false
	foundCgroupBreakout := false

	for _, f := range findings {
		if f.ID == "CVE-2024-21626" {
			foundLeakyVessels = true
		}
		if f.ID == "CVE-2022-0492" {
			foundCgroupBreakout = true
		}
	}

	if !foundLeakyVessels {
		t.Errorf("Expected CVE-2024-21626 (Leaky Vessels) to be triggered by host FD leak")
	}
	if !foundCgroupBreakout {
		t.Errorf("Expected CVE-2022-0492 (cgroup breakout) to be triggered by CAP_SYS_ADMIN + writable /sys")
	}
}

func TestLoadCVEDatabase(t *testing.T) {
	db := LoadCVEDatabase()
	if db == nil {
		t.Fatalf("LoadCVEDatabase returned nil")
	}
	if len(db.Rules) < 20 {
		t.Errorf("Expected at least 20 CVE rules in embedded database, got %d", len(db.Rules))
	}
}
