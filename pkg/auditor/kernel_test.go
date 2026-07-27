package auditor

import (
	"testing"
)

func TestAuditKernelAttackSurface(t *testing.T) {
	result, err := AuditKernelAttackSurface()
	if err != nil {
		t.Fatalf("AuditKernelAttackSurface failed: %v", err)
	}

	if result == nil {
		t.Fatal("expected non-nil KernelAuditResult")
	}

	if result.Score < 0 || result.Score > 100 {
		t.Errorf("Score out of bounds: %d", result.Score)
	}

	t.Logf("Kernel Attack Surface Score: %d/100, Sysctls Evaluated: %d", result.Score, len(result.Sysctls))
	for _, sys := range result.Sysctls {
		t.Logf(" - %s: %s (Secure: %v)", sys.Key, sys.CurrentValue, sys.IsSecure)
	}
}
