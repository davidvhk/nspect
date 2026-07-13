package server

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"

	"nspect/pkg/auditor"
	"nspect/pkg/util"
)

// Start starts the lightweight web server on the specified host and port.
func Start(host string, port int) error {
	addr := fmt.Sprintf("%s:%d", host, port)
	
	// Create listener first to fail early if port is taken
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}
	defer listener.Close()

	mux := http.NewServeMux()
	
	// Register route handlers
	mux.HandleFunc("/", handleHome)
	mux.HandleFunc("/api/containers", handleListContainers)
	mux.HandleFunc("/api/audit/", handleAudit)

	fmt.Printf("%s[+] Starting nspect web console on http://%s:%d%s\n", auditor.Bold+auditor.Green, host, port, auditor.Reset)
	fmt.Printf("[+] Auditing server ready. Scan isolated containers or input target PIDs.\n")
	
	return http.Serve(listener, mux)
}

// writeJSON Helper to output JSON responses
func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

// handleHome serves the HTML dashboard UI
func handleHome(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(DashboardHTML))
}

// handleListContainers lists all isolated processes running on the host
func handleListContainers(w http.ResponseWriter, r *http.Request) {
	processes, err := auditor.FindIsolatedProcesses()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": fmt.Sprintf("Failed to scan processes: %v", err),
		})
		return
	}
	
	// Return empty array instead of null if empty
	if processes == nil {
		processes = []auditor.IsolatedProcess{}
	}
	writeJSON(w, http.StatusOK, processes)
}

// handleAudit processes live audit requests
// Routes supported:
// - /api/audit/<pid> -> returns JSON report
// - /api/audit/<pid>/json -> downloads JSON file
// - /api/audit/<pid>/html -> downloads HTML file
func handleAudit(w http.ResponseWriter, r *http.Request) {
	// Parse PID and sub-action from URL path
	pathParts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/audit/"), "/")
	if len(pathParts) == 0 || pathParts[0] == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Missing target PID"})
		return
	}

	pidStr := pathParts[0]
	pid, err := strconv.Atoi(pidStr)
	if err != nil || pid <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid PID"})
		return
	}

	// Option to mask environment variables (default true for web dashboard safety)
	maskSecrets := true
	maskParam := r.URL.Query().Get("mask")
	if maskParam == "false" {
		maskSecrets = false
	}

	// Check if process exists and is accessible
	if !util.ProcessExists(pid) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": fmt.Sprintf("Process PID %d does not exist or is not accessible", pid)})
		return
	}

	name, err := util.GetProcessName(pid)
	if err != nil {
		name = "unknown"
	}

	cmdline, _ := util.GetCmdline(pid)

	// Run live audit report
	report, err := auditor.GenerateReport(pid, name, cmdline, maskSecrets)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": fmt.Sprintf("Audit run failed: %v", err),
		})
		return
	}

	// Resolve the sub-action (if any)
	action := ""
	if len(pathParts) > 1 {
		action = pathParts[1]
	}

	switch action {
	case "html":
		htmlStr, err := report.RenderHTML()
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to render HTML report"})
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=nspect_report_%d.html", pid))
		w.Write([]byte(htmlStr))

	case "json":
		jsonStr, err := report.RenderJSON()
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to render JSON report"})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=nspect_report_%d.json", pid))
		w.Write([]byte(jsonStr))

	case "":
		// Direct API response
		writeJSON(w, http.StatusOK, report)

	default:
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("Unknown action: %s", action)})
	}
}

// Fallback for self audit or server details
func GetServerPID() int {
	return os.Getpid()
}
