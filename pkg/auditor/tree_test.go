package auditor

import (
	"os"
	"testing"
)

func TestAuditProcessTree_Self(t *testing.T) {
	selfPID := os.Getpid()
	treeResult, err := AuditProcessTree(selfPID)
	if err != nil {
		t.Fatalf("AuditProcessTree failed on self PID %d: %v", selfPID, err)
	}

	if treeResult == nil {
		t.Fatalf("expected non-nil treeResult")
	}

	if treeResult.TargetPID != selfPID {
		t.Errorf("TargetPID = %d; want %d", treeResult.TargetPID, selfPID)
	}

	if treeResult.TotalNodes <= 0 {
		t.Errorf("TotalNodes = %d; want > 0", treeResult.TotalNodes)
	}

	if treeResult.TreeASCII == "" {
		t.Errorf("expected non-empty TreeASCII string")
	}
}
