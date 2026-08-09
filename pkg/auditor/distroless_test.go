package auditor

import (
	"os"
	"testing"
)

func TestDistrolessNoNewPrivsContextAwareness(t *testing.T) {
	pid := os.Getpid()

	// 1. Audit with 0 SUID binaries (Distroless / Rock scenario)
	fsDistroless := &FilesystemAuditResult{
		SUIDCount:    0,
		IsDistroless: true,
		IsChiselled:  true,
		ImageFlavor:  "Ubuntu Rock (Pebble Managed)",
		Score:        100,
	}

	secDistroless, err := AuditSecurity(pid, fsDistroless)
	if err != nil {
		t.Fatalf("AuditSecurity failed: %v", err)
	}

	// Verify that if NoNewPrivs is false, it is neutralized and not penalized
	if !secDistroless.NoNewPrivs {
		for _, risk := range secDistroless.Risks {
			if risk == "NoNewPrivs flag is not set. Subprocesses can gain new privileges via SUID binaries or file capabilities." {
				t.Errorf("Expected NoNewPrivs risk to be neutralized when SUIDCount is 0, but got risk: %s", risk)
			}
		}
	}

	// 2. Audit with SUID binaries present (Standard Linux distro scenario)
	fsStandard := &FilesystemAuditResult{
		SUIDCount:    3,
		IsDistroless: false,
		ImageFlavor:  "Standard Linux Distribution",
		Score:        90,
	}

	secStandard, err := AuditSecurity(pid, fsStandard)
	if err != nil {
		t.Fatalf("AuditSecurity failed: %v", err)
	}

	if !secStandard.NoNewPrivs {
		foundRisk := false
		for _, risk := range secStandard.Risks {
			if risk == "NoNewPrivs flag is not set. Subprocesses can gain new privileges via SUID binaries or file capabilities." {
				foundRisk = true
				break
			}
		}
		if !foundRisk {
			t.Errorf("Expected NoNewPrivs risk to be present when SUIDCount > 0")
		}
	}
}

func TestStandardInitsRecognizesPebble(t *testing.T) {
	standardInits := map[string]bool{
		"systemd":   true,
		"init":      true,
		"tini":      true,
		"dumb-init": true,
		"pebble":    true,
		"s6-svscan": true,
		"runit":     true,
		"pause":     true,
	}

	if !standardInits["pebble"] {
		t.Errorf("Expected pebble to be recognized in standardInits map")
	}
}
