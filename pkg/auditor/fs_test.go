package auditor

import (
	"testing"
)

func TestAuditFilesystem_NonExistentPID(t *testing.T) {
	result, err := AuditFilesystem(999999)
	if err != nil {
		t.Fatalf("Expected no error for non-existent PID, got: %v", err)
	}
	if result.Score != 100 {
		t.Errorf("Expected score 100 for skipped filesystem audit, got: %d", result.Score)
	}
	if len(result.Recommendations) != 1 {
		t.Errorf("Expected 1 recommendation about skipping, got: %d", len(result.Recommendations))
	}
}
