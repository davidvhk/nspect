package auditor

import (
	"testing"
)

func TestParseSystemdDirectives(t *testing.T) {
	unitContent := `[Unit]
Description=Test Web Service
After=network.target

[Service]
ExecStart=/usr/bin/testserver
NoNewPrivileges=yes
ProtectSystem=full
ProtectHome=yes
MemoryMax=512M
`

	kv := parseSystemdDirectives(unitContent)
	if kv["NoNewPrivileges"] != "yes" {
		t.Errorf("NoNewPrivileges = %q; want yes", kv["NoNewPrivileges"])
	}
	if kv["ProtectSystem"] != "full" {
		t.Errorf("ProtectSystem = %q; want full", kv["ProtectSystem"])
	}
	if kv["ProtectHome"] != "yes" {
		t.Errorf("ProtectHome = %q; want yes", kv["ProtectHome"])
	}
	if kv["MemoryMax"] != "512M" {
		t.Errorf("MemoryMax = %q; want 512M", kv["MemoryMax"])
	}
}

func TestAuditSystemd_Mock(t *testing.T) {
	// Test unit finding for non-existent service
	res, err := AuditSystemd(1, "nonexistent-service-foo-bar")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res != nil {
		t.Errorf("expected nil result for non-existent service unit")
	}
}
