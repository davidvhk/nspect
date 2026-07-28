package auditor

import (
	"testing"
)

func TestFindIsolatedProcesses(t *testing.T) {
	procs, err := FindIsolatedProcesses()
	if err != nil {
		t.Fatalf("FindIsolatedProcesses failed: %v", err)
	}

	t.Logf("Processes Found: %d", len(procs))
	if len(procs) == 0 {
		t.Error("expected FindIsolatedProcesses to return at least 1 process")
	}

	for i, p := range procs {
		if i < 5 {
			t.Logf(" - PID: %d, Name: %s, Score: %d", p.PID, p.Name, p.Score)
		}
	}
}
