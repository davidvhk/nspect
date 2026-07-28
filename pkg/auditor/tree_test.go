package auditor

import (
	"os"
	"strings"
	"testing"
)

func TestAuditProcessTree_LineageFiltering(t *testing.T) {
	// Test tree generation for current process
	selfPID := os.Getpid()
	result, err := AuditProcessTree(selfPID)
	if err != nil {
		t.Fatalf("AuditProcessTree failed: %v", err)
	}

	if result == nil || result.TreeASCII == "" {
		t.Fatal("expected non-empty TreeASCII")
	}

	if !strings.Contains(result.TreeASCII, "[TARGET PROCESS]") {
		t.Error("TreeASCII should contain [TARGET PROCESS]")
	}

	t.Logf("Filtered Process Lineage Nodes: %d", result.TotalNodes)
	t.Logf("Filtered Tree ASCII:\n%s", result.TreeASCII)
}
