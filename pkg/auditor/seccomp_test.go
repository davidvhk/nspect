package auditor

import (
	"strings"
	"testing"
)

func TestFormatSeccompAction(t *testing.T) {
	tests := []struct {
		input    uint32
		expected string
	}{
		{0x7fff0000, "SECCOMP_RET_ALLOW"},
		{0x80000000, "SECCOMP_RET_KILL_PROCESS"},
		{0x00000000, "SECCOMP_RET_KILL_THREAD"},
		{0x00030000, "SECCOMP_RET_TRAP"},
		{0x00050001, "SECCOMP_RET_ERRNO (EPERM)"},
		{0x0005000d, "SECCOMP_RET_ERRNO (EACCES)"},
		{0x00050026, "SECCOMP_RET_ERRNO (ENOSYS)"},
		{0x00050005, "SECCOMP_RET_ERRNO (5)"},
		{0x7fc00000, "SECCOMP_RET_USER_NOTIF"},
		{0x7fe00000, "SECCOMP_RET_TRACE"},
		{0x7ffc0000, "SECCOMP_RET_LOG"},
	}

	for _, tt := range tests {
		result := FormatSeccompAction(tt.input)
		if result != tt.expected {
			t.Errorf("FormatSeccompAction(0x%08x) = %q; want %q", tt.input, result, tt.expected)
		}
	}
}

func TestClassifyActionName(t *testing.T) {
	if classifyActionName(0x7fff0000) != "ALLOW" {
		t.Errorf("expected ALLOW")
	}
	if classifyActionName(0x80000000) != "KILL_PROCESS" {
		t.Errorf("expected KILL_PROCESS")
	}
	if classifyActionName(0x00050001) != "ERRNO" {
		t.Errorf("expected ERRNO")
	}
}

func TestAnalyzeSeccompBPF(t *testing.T) {
	// Build mock BPF filter instructions:
	// Ins 0: Load arch (offset 4)
	// Ins 1: JEQ AUDIT_ARCH_X86_64 (0xc000003e), jt=1, jf=0 -> Ins 3 if true, Ins 2 if false
	// Ins 2: RET SECCOMP_RET_KILL_PROCESS
	// Ins 3: Load syscall nr (offset 0)
	// Ins 4: JEQ 272 (unshare), jt=2, jf=0 -> Ins 7 if true, Ins 5 if false
	// Ins 5: Load args[0] (offset 16)
	// Ins 6: RET SECCOMP_RET_ALLOW (Default action)
	// Ins 7: RET SECCOMP_RET_ERRNO(1)

	prog := []SockFilter{
		{Code: bpfLd | bpfW | bpfAbs, K: 4},                  // 0: load arch
		{Code: bpfJmp | bpfJeq | bpfK, Jt: 1, Jf: 0, K: 0xc000003e}, // 1: check x86_64 -> jump 3
		{Code: bpfRet, K: seccompRetKillProcess},              // 2: kill process
		{Code: bpfLd | bpfW | bpfAbs, K: 0},                  // 3: load syscall nr
		{Code: bpfJmp | bpfJeq | bpfK, Jt: 2, Jf: 0, K: 272}, // 4: check unshare -> jump 7
		{Code: bpfLd | bpfW | bpfAbs, K: 16},                 // 5: load args[0]
		{Code: bpfRet, K: seccompRetAllow},                    // 6: default allow
		{Code: bpfRet, K: seccompRetErrno | 1},                // 7: errno EPERM
	}

	details := &SeccompAuditDetails{}
	analyzeSeccompBPF(prog, details)

	if details.InstructionCount != 8 {
		t.Errorf("InstructionCount = %d; want 8", details.InstructionCount)
	}

	if !details.ArchValidated {
		t.Errorf("expected ArchValidated to be true")
	}

	if details.ValidatedArchName != "AUDIT_ARCH_X86_64" {
		t.Errorf("ValidatedArchName = %q; want AUDIT_ARCH_X86_64", details.ValidatedArchName)
	}

	if details.DefaultReturnAction != "SECCOMP_RET_ALLOW" {
		t.Errorf("DefaultReturnAction = %q; want SECCOMP_RET_ALLOW", details.DefaultReturnAction)
	}

	if details.PolicyArchitecture != "Default-Allow (Blacklist)" {
		t.Errorf("PolicyArchitecture = %q; want Default-Allow (Blacklist)", details.PolicyArchitecture)
	}

	if !details.HasArgInspection || details.ArgInspectionCount != 1 {
		t.Errorf("ArgInspection = %v, Count = %d; want true, 1", details.HasArgInspection, details.ArgInspectionCount)
	}

	if details.ActionCounts["ALLOW"] != 1 || details.ActionCounts["KILL_PROCESS"] != 1 || details.ActionCounts["ERRNO"] != 1 {
		t.Errorf("ActionCounts breakdown mismatch: %+v", details.ActionCounts)
	}

	// Verify audited syscall unshare (272)
	foundUnshare := false
	for _, sc := range details.AuditedSyscalls {
		if sc.Name == "unshare" {
			foundUnshare = true
			if sc.Status != "Blocked/Filtered" {
				t.Errorf("unshare status = %q; want Blocked/Filtered", sc.Status)
			}
			if sc.ActionDetails != "SECCOMP_RET_ERRNO (EPERM)" {
				t.Errorf("unshare ActionDetails = %q; want SECCOMP_RET_ERRNO (EPERM)", sc.ActionDetails)
			}
		}
	}
	if !foundUnshare {
		t.Errorf("unshare syscall check not found in AuditedSyscalls")
	}
}

func TestAuditSeccompModes(t *testing.T) {
	// Mode 0 (Disabled)
	kv0 := map[string]string{"Seccomp": "0"}
	details0 := AuditSeccomp(1, kv0, false)
	if details0.Mode != 0 || details0.ModeDesc != "Disabled" {
		t.Errorf("expected Disabled seccomp mode")
	}
	if len(details0.Risks) == 0 {
		t.Errorf("expected risks for disabled seccomp")
	}

	// Mode 1 (Strict)
	kv1 := map[string]string{"Seccomp": "1"}
	details1 := AuditSeccomp(1, kv1, true)
	if details1.Mode != 1 || details1.ModeDesc != "Enabled (Strict)" {
		t.Errorf("expected Strict seccomp mode")
	}
}

func TestAnalyzeSeccompBPF_DefaultDeny(t *testing.T) {
	// Build Default-Deny (Whitelist) mock BPF filter:
	// Ins 0: Load arch (offset 4)
	// Ins 1: JEQ AUDIT_ARCH_X86_64, jt=1, jf=0 -> Ins 3
	// Ins 2: RET SECCOMP_RET_KILL_PROCESS
	// Ins 3: Load syscall nr (offset 0)
	// Ins 4: JEQ 272 (unshare), jt=1, jf=0 -> Ins 6 (RET KILL)
	// Ins 5: RET SECCOMP_RET_KILL_PROCESS (Default action)
	// Ins 6: RET SECCOMP_RET_KILL_PROCESS

	prog := []SockFilter{
		{Code: bpfLd | bpfW | bpfAbs, K: 4},
		{Code: bpfJmp | bpfJeq | bpfK, Jt: 1, Jf: 0, K: 0xc000003e},
		{Code: bpfRet, K: seccompRetKillProcess},
		{Code: bpfLd | bpfW | bpfAbs, K: 0},
		{Code: bpfJmp | bpfJeq | bpfK, Jt: 1, Jf: 0, K: 272},
		{Code: bpfRet, K: seccompRetKillProcess},
		{Code: bpfRet, K: seccompRetKillProcess},
	}

	details := &SeccompAuditDetails{}
	analyzeSeccompBPF(prog, details)

	if details.PolicyArchitecture != "Default-Deny (Whitelist)" {
		t.Errorf("PolicyArchitecture = %q; want Default-Deny (Whitelist)", details.PolicyArchitecture)
	}

	if details.DefaultReturnAction != "SECCOMP_RET_KILL_PROCESS" {
		t.Errorf("DefaultReturnAction = %q; want SECCOMP_RET_KILL_PROCESS", details.DefaultReturnAction)
	}
}

func TestAuditSeccomp_PtracePermissionError(t *testing.T) {
	// PID 1 is typically protected by YAMA or user namespace ptrace boundaries
	kv := map[string]string{"Seccomp": "2"}
	details := AuditSeccomp(1, kv, true)
	if details.Mode != 2 {
		t.Fatalf("expected mode 2")
	}

	if details.InspectionNotes != "" && !details.InspectedViaPtrace {
		foundRec := false
		for _, rec := range details.Recommendations {
			if strings.Contains(rec, "kernel.yama.ptrace_scope=0") {
				foundRec = true
				break
			}
		}
		if !foundRec {
			t.Errorf("expected YAMA ptrace_scope recommendation when ptrace inspection is restricted")
		}
	}
}
