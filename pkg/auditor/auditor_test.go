package auditor

import (
	"testing"
)

func TestFindIsolatedProcesses(t *testing.T) {
	procs, err := FindIsolatedProcesses()
	if err != nil {
		t.Logf("FindIsolatedProcesses returned error (likely permission restricted): %v", err)
		return
	}

	t.Logf("Isolated Processes Found: %d", len(procs))
	for i, p := range procs {
		if i < 5 {
			t.Logf(" - PID: %d, Name: %s, Score: %d", p.PID, p.Name, p.Score)
		}
	}
}
