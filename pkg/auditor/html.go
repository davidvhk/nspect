package auditor

import (
	"bytes"
	"html/template"
	"strings"
)

// RenderHTML generates a beautiful self-contained static HTML audit report.
func (r *AuditReport) RenderHTML() (string, error) {
	funcMap := template.FuncMap{
		"scoreClass": func(score int) string {
			if score < 50 {
				return "low"
			}
			if score < 80 {
				return "medium"
			}
			return "high"
		},
		"lower": strings.ToLower,
		"riskClass": func(level string) string {
			switch strings.ToLower(level) {
			case "critical":
				return "risk-critical"
			case "high":
				return "risk-high"
			case "medium":
				return "risk-medium"
			case "low":
				return "risk-low"
			default:
				return "risk-info"
			}
		},
		"recs": func(rep *AuditReport) []string {
			var recs []string
			if rep.Security != nil {
				recs = append(recs, rep.Security.Recommendations...)
			}
			if rep.Mounts != nil {
				recs = append(recs, rep.Mounts.Recommendations...)
			}
			if rep.Filesystem != nil {
				recs = append(recs, rep.Filesystem.Recommendations...)
			}
			if rep.Env != nil && len(rep.Env.Secrets) > 0 {
				recs = append(recs, "Do not expose passwords, API keys, or security tokens in environment variables. Use secret stores (e.g. Docker Secrets, K8s Secrets, HashiCorp Vault) or mount credentials securely as files.")
			}
			if rep.FD != nil {
				for _, fd := range rep.FD.FDs {
					if fd.IsHighRisk && fd.Type == "Directory" {
						recs = append(recs, "Ensure file descriptors pointing to host directories are closed before spawning container processes (ensure O_CLOEXEC is set on host file descriptors).")
						break
					}
				}
			}
			return recs
		},
		"hasFDRisks": func(rep *AuditReport) bool {
			if rep.FD == nil {
				return false
			}
			for _, fd := range rep.FD.FDs {
				if fd.IsHighRisk {
					return true
				}
			}
			return false
		},
		"join": strings.Join,
		"multiply": func(a int, b float64) float64 {
			return float64(a) * b
		},
		"sub": func(a, b int) int {
			return a - b
		},
		"add": func(a, b int) int {
			return a + b
		},
	}

	tmpl, err := template.New("report").Funcs(funcMap).Parse(htmlTemplate)
	if err != nil {
		return "", err
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, r); err != nil {
		return "", err
	}

	return buf.String(), nil
}

const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>nspect Audit Report - {{.ProcessName}} (PID {{.PID}})</title>
    <style>
        :root {
            --bg-main: #030712;
            --bg-card: #0f172a;
            --bg-card-hover: #1e293b;
            --border-color: #1e293b;
            --text-primary: #f9fafb;
            --text-secondary: #9ca3af;
            --color-primary: #3b82f6;
            
            --critical: #ef4444;
            --high: #f97316;
            --medium: #eab308;
            --low: #3b82f6;
            --info: #10b981;
            
            --critical-bg: rgba(239, 68, 68, 0.15);
            --high-bg: rgba(249, 115, 22, 0.15);
            --medium-bg: rgba(234, 179, 8, 0.15);
            --low-bg: rgba(59, 130, 246, 0.15);
            --info-bg: rgba(16, 185, 129, 0.15);
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background-color: var(--bg-main);
            color: var(--text-primary);
            line-height: 1.5;
            padding: 2rem 1rem;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
        }

        header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 1.5rem;
            margin-bottom: 2rem;
            flex-wrap: wrap;
            gap: 1.5rem;
        }

        .title-area h1 {
            font-size: 1.8rem;
            font-weight: 700;
            background: linear-gradient(to right, #60a5fa, #3b82f6, #2563eb);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 0.5rem;
        }

        .title-area p {
            color: var(--text-secondary);
            font-size: 0.95rem;
        }

        .cmdline {
            font-family: monospace;
            background-color: #020617;
            padding: 0.2rem 0.5rem;
            border-radius: 4px;
            border: 1px solid var(--border-color);
            margin-left: 0.5rem;
        }

        /* Score Circle styling */
        .score-box {
            display: flex;
            align-items: center;
            gap: 1rem;
            background-color: var(--bg-card);
            padding: 1rem 1.5rem;
            border-radius: 12px;
            border: 1px solid var(--border-color);
        }

        .score-circle {
            position: relative;
            width: 80px;
            height: 80px;
        }

        .score-circle svg {
            transform: rotate(-90deg);
            width: 100%;
            height: 100%;
        }

        .score-circle circle {
            fill: none;
            stroke-width: 8;
        }

        .score-circle .bg {
            stroke: #1e293b;
        }

        .score-circle .bar {
            stroke-dasharray: 226;
            stroke-linecap: round;
            transition: stroke-dashoffset 1s ease-in-out;
        }

        .score-circle.low .bar { stroke: var(--critical); }
        .score-circle.medium .bar { stroke: var(--medium); }
        .score-circle.high .bar { stroke: var(--info); }

        .score-text {
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            font-size: 1.25rem;
            font-weight: 700;
        }

        .score-label h3 {
            font-size: 1.1rem;
            margin-bottom: 0.2rem;
        }

        .score-label p {
            font-size: 0.85rem;
            color: var(--text-secondary);
        }

        /* Grid layout */
        .dashboard-grid {
            display: grid;
            grid-template-columns: 320px 1fr;
            gap: 2rem;
        }

        @media (max-width: 900px) {
            .dashboard-grid {
                grid-template-columns: 1fr;
            }
        }

        /* Sidebar / Overview Panel */
        .sidebar {
            display: flex;
            flex-direction: column;
            gap: 1.5rem;
        }

        .card {
            background-color: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 1.5rem;
        }

        .card h2 {
            font-size: 1.1rem;
            font-weight: 600;
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 0.75rem;
            margin-bottom: 1rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }

        .meta-list {
            list-style: none;
            display: flex;
            flex-direction: column;
            gap: 0.75rem;
        }

        .meta-item {
            display: flex;
            justify-content: space-between;
            font-size: 0.9rem;
        }

        .meta-item span:first-child {
            color: var(--text-secondary);
        }

        .meta-item span:last-child {
            font-weight: 500;
        }

        /* Remediations Checklist */
        .remediations-list {
            list-style: none;
            display: flex;
            flex-direction: column;
            gap: 1rem;
        }

        .remediation-item {
            display: flex;
            gap: 0.75rem;
            font-size: 0.9rem;
            background-color: #020617;
            padding: 0.75rem;
            border-radius: 8px;
            border-left: 3px solid var(--color-primary);
        }

        .remediation-num {
            font-weight: 700;
            color: var(--color-primary);
        }

        /* Main Section detailing */
        .main-content {
            display: flex;
            flex-direction: column;
            gap: 1.5rem;
        }

        details {
            background-color: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            overflow: hidden;
            transition: border-color 0.2s;
        }

        details[open] {
            border-color: #3b82f6;
        }

        summary {
            padding: 1.25rem 1.5rem;
            font-weight: 600;
            font-size: 1.1rem;
            cursor: pointer;
            list-style: none;
            display: flex;
            justify-content: space-between;
            align-items: center;
            user-select: none;
            outline: none;
            transition: background-color 0.2s;
        }

        summary:hover {
            background-color: var(--bg-card-hover);
        }

        summary::-webkit-details-marker {
            display: none;
        }

        .summary-left {
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }

        .summary-right {
            display: flex;
            align-items: center;
            gap: 1rem;
        }

        .caret {
            width: 18px;
            height: 18px;
            transition: transform 0.2s;
            fill: var(--text-secondary);
        }

        details[open] summary .caret {
            transform: rotate(180deg);
        }

        .section-content {
            padding: 1.5rem;
            border-top: 1px solid var(--border-color);
            background-color: #020617;
        }

        /* Badges */
        .badge {
            padding: 0.25rem 0.6rem;
            font-size: 0.8rem;
            font-weight: 600;
            border-radius: 9999px;
            text-transform: uppercase;
        }

        .badge.score {
            background-color: #1e293b;
        }
        .badge.score.low { color: var(--critical); }
        .badge.score.medium { color: var(--medium); }
        .badge.score.high { color: var(--info); }

        .badge.risk-critical { background-color: var(--critical-bg); color: var(--critical); border: 1px solid var(--critical); }
        .badge.risk-high { background-color: var(--high-bg); color: var(--high); border: 1px solid var(--high); }
        .badge.risk-medium { background-color: var(--medium-bg); color: var(--medium); border: 1px solid var(--medium); }
        .badge.risk-low { background-color: var(--low-bg); color: var(--low); border: 1px solid var(--low); }
        .badge.risk-info { background-color: var(--info-bg); color: var(--info); border: 1px solid var(--info); }

        /* Tables */
        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 0.9rem;
            text-align: left;
            margin-top: 0.5rem;
        }

        th, td {
            padding: 0.75rem 1rem;
            border-bottom: 1px solid var(--border-color);
        }

        th {
            font-weight: 600;
            color: var(--text-secondary);
            background-color: var(--bg-card);
        }

        tr:last-child td {
            border-bottom: none;
        }

        /* Risks list under sections */
        .risk-list {
            display: flex;
            flex-direction: column;
            gap: 1rem;
        }

        .risk-card {
            background-color: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 1rem;
        }

        .risk-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 0.5rem;
            flex-wrap: wrap;
            gap: 0.5rem;
        }

        .risk-title {
            font-family: monospace;
            font-weight: 700;
            font-size: 0.95rem;
        }

        .risk-desc {
            font-size: 0.9rem;
            color: var(--text-secondary);
        }

        /* Search Filter Input */
        .search-container {
            margin-bottom: 1rem;
            position: relative;
        }

        .search-input {
            width: 100%;
            background-color: var(--bg-card);
            border: 1px solid var(--border-color);
            color: var(--text-primary);
            padding: 0.6rem 1rem;
            border-radius: 6px;
            font-size: 0.85rem;
            outline: none;
            transition: border-color 0.2s;
        }

        .search-input:focus {
            border-color: var(--color-primary);
        }

        /* Sockets mapping formatting */
        .socket-row {
            display: flex;
            justify-content: space-between;
            padding: 0.5rem 0;
            border-bottom: 1px solid var(--border-color);
            font-family: monospace;
            font-size: 0.85rem;
        }

        .socket-row:last-child {
            border-bottom: none;
        }

        .socket-label {
            color: var(--text-secondary);
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="title-area">
                <h1>nspect Sandbox Audit Report</h1>
                <p>Process: <strong>{{.ProcessName}}</strong> (PID: {{.PID}}) <span class="cmdline">{{.Cmdline}}</span></p>
            </div>
            <div class="score-box">
                <div class="score-circle {{scoreClass .OverallScore}}">
                    <svg viewBox="0 0 80 80">
                        <circle class="bg" cx="40" cy="40" r="36" />
                        <circle class="bar" cx="40" cy="40" r="36" stroke-dashoffset="{{multiply (sub 100 .OverallScore) 2.26}}" />
                    </svg>
                    <div class="score-text">{{.OverallScore}}</div>
                </div>
                <div class="score-label">
                    <h3>Overall Score</h3>
                    <p>Weight-averaged security status</p>
                </div>
            </div>
        </header>

        <div class="dashboard-grid">
            <!-- Sidebar: Overview & Remediations -->
            <div class="sidebar">
                <!-- Overview Card -->
                <div class="card">
                    <h2>
                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                        Auditor Status
                    </h2>
                    <ul class="meta-list">
                        <li class="meta-item">
                            <span>UID/EUID</span>
                            <span>{{.Security.UID}} / {{.Security.EUID}}</span>
                        </li>
                        <li class="meta-item">
                            <span>Rootless Sandbox</span>
                            <span>{{if .Security.UserNSMapped}}<span style="color:var(--info)">Yes</span>{{else}}<span style="color:var(--critical)">No</span>{{end}}</span>
                        </li>
                        <li class="meta-item">
                            <span>LSM State</span>
                            <span>{{.Security.LSMProfile}}</span>
                        </li>
                        <li class="meta-item">
                            <span>NoNewPrivs</span>
                            <span>{{if .Security.NoNewPrivs}}Yes{{else}}No{{end}}</span>
                        </li>
                        <li class="meta-item">
                            <span>Seccomp filter</span>
                            <span>{{if eq .Security.SeccompMode 2}}Enabled{{else}}Disabled{{end}}</span>
                        </li>
                    </ul>
                </div>

                <!-- Remediations Card -->
                {{$remediationList := recs .}}
                {{if $remediationList}}
                <div class="card">
                    <h2>
                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
                        Remediations
                    </h2>
                    <div class="remediations-list">
                        {{range $index, $rec := $remediationList}}
                        <div class="remediation-item">
                            <span class="remediation-num">{{add $index 1}}</span>
                            <span>{{$rec}}</span>
                        </div>
                        {{end}}
                    </div>
                </div>
                {{end}}
            </div>

            <!-- Main Panels -->
            <div class="main-content">
                <!-- 1. Namespace Isolation -->
                <details>
                    <summary>
                        <div class="summary-left">
                            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="9"/><rect x="14" y="3" width="7" height="5"/><rect x="14" y="12" width="7" height="9"/><rect x="3" y="16" width="7" height="5"/></svg>
                            <span>[1] Namespace Isolation</span>
                        </div>
                        <div class="summary-right">
                            <span class="badge score {{scoreClass .Namespaces.Score}}">Score: {{.Namespaces.Score}}/100</span>
                            <svg class="caret" viewBox="0 0 24 24"><path d="M7 10l5 5 5-5H7z"/></svg>
                        </div>
                    </summary>
                    <div class="section-content">
                        <table>
                            <thead>
                                <tr>
                                    <th>Namespace</th>
                                    <th>Status</th>
                                    <th>Target Inode</th>
                                    <th>Risk / Exposure</th>
                                </tr>
                            </thead>
                            <tbody>
                                {{range .Namespaces.Namespaces}}
                                <tr>
                                    <td><strong>{{.Name}}</strong></td>
                                    <td>
                                        {{if .IsSharedWithHost}}
                                        <span class="badge risk-critical">Shared</span>
                                        {{else}}
                                        <span class="badge risk-info">Isolated</span>
                                        {{end}}
                                    </td>
                                    <td><span style="font-family: monospace;">{{.TargetInode}}</span></td>
                                    <td style="color: var(--text-secondary); font-size: 0.85rem;">
                                        {{if .IsSharedWithHost}}{{.Description}}{{else}}Protected by isolation{{end}}
                                    </td>
                                </tr>
                                {{end}}
                            </tbody>
                        </table>
                    </div>
                </details>

                <!-- 2. Process Security Context -->
                <details>
                    <summary>
                        <div class="summary-left">
                            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
                            <span>[2] Process Security Context</span>
                        </div>
                        <div class="summary-right">
                            <span class="badge score {{scoreClass .Security.Score}}">Score: {{.Security.Score}}/100</span>
                            <svg class="caret" viewBox="0 0 24 24"><path d="M7 10l5 5 5-5H7z"/></svg>
                        </div>
                    </summary>
                    <div class="section-content">
                        <table style="margin-bottom: 1.5rem;">
                            <thead>
                                <tr>
                                    <th>Metric</th>
                                    <th>Value</th>
                                </tr>
                            </thead>
                            <tbody>
                                <tr>
                                    <td>User Identity (UID/EUID)</td>
                                    <td>
                                        UID={{.Security.UID}}, EUID={{.Security.EUID}}
                                        {{if eq .Security.EUID 0}}
                                            {{if .Security.UserNSMapped}}
                                                <span class="badge risk-low" style="margin-left: 0.5rem;">Rootless / Mapped</span>
                                            {{else}}
                                                <span class="badge risk-critical" style="margin-left: 0.5rem;">Host Root</span>
                                            {{end}}
                                        {{end}}
                                    </td>
                                </tr>
                                <tr>
                                    <td>Group Identity (GID/EGID)</td>
                                    <td>GID={{.Security.GID}}, EGID={{.Security.EGID}}</td>
                                </tr>
                                <tr>
                                    <td>Seccomp Mode</td>
                                    <td>
                                        {{if eq .Security.SeccompMode 2}}
                                        <span class="badge risk-info">Enabled (Filter)</span>
                                        {{else if eq .Security.SeccompMode 1}}
                                        <span class="badge risk-info">Enabled (Strict)</span>
                                        {{else}}
                                        <span class="badge risk-critical">Disabled</span>
                                        {{end}}
                                    </td>
                                </tr>
                                <tr>
                                    <td>NoNewPrivs State</td>
                                    <td>
                                        {{if .Security.NoNewPrivs}}
                                        <span class="badge risk-info">Enabled</span>
                                        {{else}}
                                        <span class="badge risk-medium">Disabled</span>
                                        {{end}}
                                    </td>
                                </tr>
                                <tr>
                                    <td>LSM Profile</td>
                                    <td><span style="font-family: monospace;">{{.Security.LSMProfile}}</span></td>
                                </tr>
                                {{if .Security.SetgroupsStatus}}
                                <tr>
                                    <td>Setgroups Policy</td>
                                    <td>{{.Security.SetgroupsStatus}}</td>
                                </tr>
                                {{end}}
                                {{if .Security.InitProcessName}}
                                <tr>
                                    <td>PID 1 Init Executable</td>
                                    <td><span style="font-family: monospace;">{{.Security.InitProcessName}}</span></td>
                                </tr>
                                {{end}}
                                <tr>
                                    <td>Cgroup Limits (Memory / PIDs)</td>
                                    <td>Memory: {{.Security.CgroupMemoryLimit}} | PIDs: {{.Security.CgroupPidsLimit}}</td>
                                </tr>
                            </tbody>
                        </table>

                        {{if .Security.Risks}}
                        <div style="font-weight: 600; color: var(--medium); margin-bottom: 0.5rem;">Context Hardening Issues:</div>
                        <ul class="meta-list" style="margin-left: 1.5rem; list-style-type: disc;">
                            {{range .Security.Risks}}
                            <li style="font-size: 0.9rem; color: var(--text-secondary); margin-bottom: 0.25rem;">{{.}}</li>
                            {{end}}
                        </ul>
                        {{end}}
                    </div>
                </details>

                <!-- 3. Linux Capabilities -->
                <details>
                    <summary>
                        <div class="summary-left">
                            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"/></svg>
                            <span>[3] Linux Capabilities</span>
                        </div>
                        <div class="summary-right">
                            <span class="badge score {{scoreClass .Capabilities.Score}}">Score: {{.Capabilities.Score}}/100</span>
                            <svg class="caret" viewBox="0 0 24 24"><path d="M7 10l5 5 5-5H7z"/></svg>
                        </div>
                    </summary>
                    <div class="section-content">
                        <div class="card" style="padding: 1rem; margin-bottom: 1.5rem; background-color: #0c111d;">
                            <div style="font-size: 0.85rem; color: var(--text-secondary); margin-bottom: 0.5rem; font-weight: 600;">ACTIVE EFFECTIVE CAPABILITIES:</div>
                            <div style="font-family: monospace; font-size: 0.9rem; word-break: break-all;">
                                {{if .Capabilities.Sets.Effective}}
                                    {{join .Capabilities.Sets.Effective ", "}}
                                {{else}}
                                    [None / All Capabilities Dropped]
                                {{end}}
                            </div>
                        </div>

                        {{if .Capabilities.HighRiskCaps}}
                        <div style="font-weight: 600; margin-bottom: 0.75rem;">Sensitive Capabilities Audit:</div>
                        <div class="risk-list">
                            {{range .Capabilities.HighRiskCaps}}
                            <div class="risk-card">
                                <div class="risk-header">
                                    <span class="risk-title">{{.Name}}</span>
                                    <span class="badge {{riskClass .RiskLevel}}">{{.RiskLevel}}</span>
                                </div>
                                <div class="risk-desc">{{.Description}}</div>
                            </div>
                            {{end}}
                        </div>
                        {{else}}
                        <div style="color: var(--info); font-size: 0.9rem;">No sensitive capabilities found in active set.</div>
                        {{end}}
                    </div>
                </details>

                <!-- 4. Mount & Volume Exposure -->
                <details id="mounts-panel">
                    <summary>
                        <div class="summary-left">
                            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21.21 15.89A10 10 0 1 1 8 2.83M22 12A10 10 0 0 0 12 2v10z"/></svg>
                            <span>[4] Mount & Volume Exposure</span>
                        </div>
                        <div class="summary-right">
                            <span class="badge score {{scoreClass .Mounts.Score}}">Score: {{.Mounts.Score}}/100</span>
                            <svg class="caret" viewBox="0 0 24 24"><path d="M7 10l5 5 5-5H7z"/></svg>
                        </div>
                    </summary>
                    <div class="section-content">
                        <div class="search-container">
                            <input type="text" id="mount-search" class="search-input" placeholder="Search mount points or filesystems (e.g. /proc, overlay)..." onkeyup="filterMounts()">
                        </div>
                        <div style="font-size: 0.85rem; color: var(--text-secondary); margin-bottom: 0.75rem;">
                            Total Mount Points Evaluated: <strong>{{len .Mounts.Mounts}}</strong>
                        </div>

                        {{if .Mounts.Risks}}
                        <div class="risk-list" id="mounts-list">
                            {{range .Mounts.Risks}}
                            <div class="risk-card mount-risk-item" data-point="{{.MountPoint}}" data-source="{{.MountSource}}" data-fs="{{.FSType}}">
                                <div class="risk-header">
                                    <span class="risk-title">{{.MountSource}} &rarr; {{.MountPoint}} ({{.FSType}})</span>
                                    <span class="badge {{riskClass .RiskLevel}}">{{.RiskLevel}}</span>
                                </div>
                                <div class="risk-desc">{{.Description}}</div>
                            </div>
                            {{end}}
                        </div>
                        {{else}}
                        <div style="color: var(--info); font-size: 0.9rem;">No sensitive volume exposures or writeable kernel mounts detected.</div>
                        {{end}}
                    </div>
                </details>

                <!-- 5. File Descriptor Leak Scan -->
                <details>
                    <summary>
                        <div class="summary-left">
                            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/></svg>
                            <span>[5] File Descriptor Leak Scan</span>
                        </div>
                        <div class="summary-right">
                            <span class="badge score {{scoreClass .FD.Score}}">Score: {{.FD.Score}}/100</span>
                            <svg class="caret" viewBox="0 0 24 24"><path d="M7 10l5 5 5-5H7z"/></svg>
                        </div>
                    </summary>
                    <div class="section-content">
                        <div style="font-size: 0.85rem; color: var(--text-secondary); margin-bottom: 1rem;">
                            Total open file descriptors: <strong>{{len .FD.FDs}}</strong>
                        </div>

                        {{if hasFDRisks .}}
                        <div class="risk-list">
                            {{range .FD.FDs}}
                                {{if .IsHighRisk}}
                                <div class="risk-card">
                                    <div class="risk-header">
                                        <span class="risk-title">FD {{.FD}} &rarr; {{.Target}} ({{.Type}})</span>
                                        <span class="badge risk-critical">High Risk</span>
                                    </div>
                                    <div class="risk-desc">{{.Description}}</div>
                                </div>
                                {{end}}
                            {{end}}
                        </div>
                        {{else}}
                        <div style="color: var(--info); font-size: 0.9rem;">No dangerous host file descriptors or sensitive directory leaks detected.</div>
                        {{end}}
                    </div>
                </details>

                <!-- 6. Environment Secret Scan -->
                <details>
                    <summary>
                        <div class="summary-left">
                            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="2" width="20" height="8" rx="2" ry="2"/><rect x="2" y="14" width="20" height="8" rx="2" ry="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/></svg>
                            <span>[6] Environment Secret Scan</span>
                        </div>
                        <div class="summary-right">
                            <span class="badge score {{scoreClass .Env.Score}}">Score: {{.Env.Score}}/100</span>
                            <svg class="caret" viewBox="0 0 24 24"><path d="M7 10l5 5 5-5H7z"/></svg>
                        </div>
                    </summary>
                    <div class="section-content">
                        {{if .Env.Secrets}}
                        <div style="font-weight: 600; color: var(--critical); margin-bottom: 0.5rem; font-size: 0.9rem;">Exposed Sensitive Environment Variables:</div>
                        <table>
                            <thead>
                                <tr>
                                    <th>Variable Key</th>
                                    <th>Value</th>
                                </tr>
                            </thead>
                            <tbody>
                                {{range .Env.Secrets}}
                                <tr>
                                    <td><span style="font-family: monospace; font-weight: 700; color: #ef4444;">{{.Key}}</span></td>
                                    <td><span style="font-family: monospace;">{{.Value}}</span></td>
                                </tr>
                                {{end}}
                            </tbody>
                        </table>
                        {{else}}
                        <div style="color: var(--info); font-size: 0.9rem;">No sensitive environment variables matching credential patterns discovered.</div>
                        {{end}}
                    </div>
                </details>

                <!-- 7. Sockets & Network Connections -->
                <details>
                    <summary>
                        <div class="summary-left">
                            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/><path d="M3 12c0 1.66 4 3 9 3s9-1.34 9-3"/></svg>
                            <span>[7] Sockets & Network Connections</span>
                        </div>
                        <div class="summary-right">
                            <span class="badge score">Info</span>
                            <svg class="caret" viewBox="0 0 24 24"><path d="M7 10l5 5 5-5H7z"/></svg>
                        </div>
                    </summary>
                    <div class="section-content">
                        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1.5rem;">
                            <!-- Listening Sockets -->
                            <div>
                                <div style="font-weight: 600; font-size: 0.85rem; color: var(--text-secondary); margin-bottom: 0.75rem; text-transform: uppercase;">Listening Ports:</div>
                                {{if .Network.ListeningPorts}}
                                    {{range .Network.ListeningPorts}}
                                    <div class="socket-row">
                                        <span>[{{.Proto}}] {{.LocalIP}}:{{.LocalPort}}</span>
                                        {{if or (eq .LocalIP "0.0.0.0") (eq .LocalIP "::")}}
                                            <span class="badge risk-critical" style="font-size: 0.7rem; padding: 0.1rem 0.4rem;">Exposed</span>
                                        {{end}}
                                    </div>
                                    {{end}}
                                {{else}}
                                    <div style="color: var(--text-secondary); font-size: 0.85rem;">No active listening ports found inside namespace.</div>
                                {{end}}
                            </div>

                            <!-- Established Connections -->
                            <div>
                                <div style="font-weight: 600; font-size: 0.85rem; color: var(--text-secondary); margin-bottom: 0.75rem; text-transform: uppercase;">Established Connections:</div>
                                {{if .Network.Connections}}
                                    {{range .Network.Connections}}
                                    <div class="socket-row">
                                        <span>[{{.Proto}}] {{.LocalIP}}:{{.LocalPort}}</span>
                                        <span class="socket-label">&rarr;</span>
                                        <span>{{.RemoteIP}}:{{.RemotePort}}</span>
                                    </div>
                                    {{end}}
                                {{else}}
                                    <div style="color: var(--text-secondary); font-size: 0.85rem;">No active established connections.</div>
                                {{end}}
                            </div>
                        </div>
                    </div>
                </details>

                <!-- 8. Container Filesystem Audit -->
                <details>
                    <summary>
                        <div class="summary-left">
                            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg>
                            <span>[8] Container Filesystem Audit</span>
                        </div>
                        <div class="summary-right">
                            <span class="badge score {{scoreClass .Filesystem.Score}}">Score: {{.Filesystem.Score}}/100</span>
                            <svg class="caret" viewBox="0 0 24 24"><path d="M7 10l5 5 5-5H7z"/></svg>
                        </div>
                    </summary>
                    <div class="section-content">
                        {{if .Filesystem.Risks}}
                        <div style="font-weight: 600; margin-bottom: 0.75rem;">Filesystem Vulnerabilities Discovered:</div>
                        <div class="risk-list">
                            {{range .Filesystem.Risks}}
                            <div class="risk-card">
                                <div class="risk-header">
                                    <span class="risk-title" style="word-break: break-all;">{{.Path}}</span>
                                    <span class="badge {{riskClass .RiskLevel}}">{{.RiskLevel}}</span>
                                </div>
                                <div class="risk-desc">{{.Description}}</div>
                            </div>
                            {{end}}
                        </div>
                        {{else}}
                        <div style="color: var(--info); font-size: 0.9rem;">No sensitive SUID/SGID binaries, insecure world-writable directories, or static env secrets found.</div>
                        {{end}}
                    </div>
                </details>
            </div>
        </div>
    </div>

    <script>
        function filterMounts() {
            var input = document.getElementById('mount-search');
            var filter = input.value.toLowerCase();
            var items = document.getElementsByClassName('mount-risk-item');

            for (var i = 0; i < items.length; i++) {
                var point = items[i].getAttribute('data-point').toLowerCase();
                var source = items[i].getAttribute('data-source').toLowerCase();
                var fs = items[i].getAttribute('data-fs').toLowerCase();

                if (point.indexOf(filter) > -1 || source.indexOf(filter) > -1 || fs.indexOf(filter) > -1) {
                    items[i].style.display = "";
                } else {
                    items[i].style.display = "none";
                }
            }
        }
    </script>
</body>
</html>`


