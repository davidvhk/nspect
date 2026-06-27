package auditor

import (
	"fmt"
	"os"
	"strings"

	"nspect/pkg/util"
)

// EnvSecret details a sensitive environment variable discovery.
type EnvSecret struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// EnvAuditResult holds findings of the environment audit.
type EnvAuditResult struct {
	Secrets []EnvSecret `json:"secrets"`
	Score   int         `json:"score"` // 0 to 100
}

// AuditEnv reads and audits environment variables of a given PID from /proc/[pid]/environ.
func AuditEnv(pid int, maskSecrets bool) (*EnvAuditResult, error) {
	envPath := util.ProcPath(pid, "environ")
	data, err := os.ReadFile(envPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read environment variables: %w", err)
	}

	var secrets []EnvSecret
	scoreReduction := 0

	// /proc/[pid]/environ is null-byte separated
	vars := strings.Split(string(data), "\x00")
	sensitiveKeys := []string{"PASS", "SECRET", "KEY", "TOKEN", "PWD", "AUTH", "CRED"}

	for _, v := range vars {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}

		parts := strings.SplitN(v, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := parts[0]
		val := parts[1]
		keyUpper := strings.ToUpper(key)

		isSensitive := false
		for _, sk := range sensitiveKeys {
			if strings.Contains(keyUpper, sk) {
				isSensitive = true
				break
			}
		}

		// Don't flag empty or trivial environment variables
		if isSensitive && val != "" {
			// Skip PWD/OLDPWD absolute path false positives
			if (keyUpper == "PWD" || keyUpper == "OLDPWD") && strings.HasPrefix(val, "/") {
				continue
			}
			displayVal := val
			if maskSecrets {
				displayVal = maskSecret(val)
			}
			secrets = append(secrets, EnvSecret{
				Key:   key,
				Value: displayVal,
			})
			scoreReduction += 15
		}
	}

	finalScore := 100 - scoreReduction
	if finalScore < 0 {
		finalScore = 0
	}

	return &EnvAuditResult{
		Secrets: secrets,
		Score:   finalScore,
	}, nil
}

// maskSecret replaces sensitive credentials with asterisks, keeping outer characters for context.
func maskSecret(val string) string {
	if len(val) <= 4 {
		return "****"
	}
	// Mask and keep first 2 and last 2 characters
	return val[:2] + strings.Repeat("*", len(val)-4) + val[len(val)-2:]
}
