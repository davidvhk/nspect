package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"

	"nspect/pkg/auditor"
	"nspect/pkg/server"
	"nspect/pkg/util"
)

func printUsage() {
	fmt.Printf("Linux Capability & Namespace Auditor (nspect)\n")
	fmt.Printf("Usage: %s [flags]\n\n", os.Args[0])
	fmt.Printf("Flags:\n")
	fmt.Printf("  -p, --pid <PID>         Audit the specified process ID\n")
	fmt.Printf("  -l, --list              List all running processes in isolated namespaces (containers/sandboxes)\n")
	fmt.Printf("  -m, --mask              Mask sensitive environment variables instead of showing them in plaintext\n")
	fmt.Printf("  -j, --json              Output report in JSON format\n")
	fmt.Printf("  -H, --html              Output report in HTML format\n")
	fmt.Printf("  -s, --server            Start lightweight web console for live auditing\n")
	fmt.Printf("      --host <host>       Host address for the web console to listen on (default: 127.0.0.1)\n")
	fmt.Printf("      --port <port>       Port for the web console to listen on (default: 8080)\n")
	fmt.Printf("  -h, --help              Show this help message\n")
	fmt.Printf("\nCI/CD Flags:\n")
	fmt.Printf("      --fail-score <score>  Fail if overall security score is less than this value (0-100)\n")
	fmt.Printf("      --fail-on-shared-ns   Fail if any namespace (mnt, pid, net, ipc, uts) is shared with host\n")
	fmt.Printf("      --fail-on-caps        Fail if any Critical or High risk capabilities are active\n")
	fmt.Printf("      --fail-on-mount-risks Fail if any Critical, High, or Medium risk mounts are found\n")
	fmt.Printf("      --fail-on-secrets     Fail if any sensitive environment secrets are found\n")
	fmt.Printf("      --fail-on-fd-leaks    Fail if any high-risk leaked host file descriptors are found\n")
	fmt.Printf("      --fail-on-fs-risks    Fail if any Critical, High, or Medium filesystem risks are found\n")
	fmt.Printf("      --fail-on-root        Fail if container is running as root on host (EUID=0 and not virtualized)\n")
}

func main() {
	var pidFlag string
	var listFlag bool
	var maskFlag bool
	var jsonFlag bool
	var htmlFlag bool
	var helpFlag bool
	var serverFlag bool
	var hostFlag string
	var portFlag int

	// CI/CD Flags
	var failScoreFlag int
	var failOnSharedNSFlag bool
	var failOnCapsFlag bool
	var failOnMountRisksFlag bool
	var failOnSecretsFlag bool
	var failOnFDLeaksFlag bool
	var failOnRootFlag bool
	var failOnFSRisksFlag bool

	flag.StringVar(&pidFlag, "pid", "", "Audit the specified process ID")
	flag.StringVar(&pidFlag, "p", "", "Audit the specified process ID")
	flag.BoolVar(&listFlag, "list", false, "List all running isolated processes")
	flag.BoolVar(&listFlag, "l", false, "List all running isolated processes")
	flag.BoolVar(&maskFlag, "mask", false, "Mask sensitive environment variables")
	flag.BoolVar(&maskFlag, "m", false, "Mask sensitive environment variables")
	flag.BoolVar(&jsonFlag, "json", false, "Output report in JSON format")
	flag.BoolVar(&jsonFlag, "j", false, "Output report in JSON format")
	flag.BoolVar(&htmlFlag, "html", false, "Output report in HTML format")
	flag.BoolVar(&htmlFlag, "H", false, "Output report in HTML format")
	flag.BoolVar(&serverFlag, "server", false, "Start lightweight web console")
	flag.BoolVar(&serverFlag, "s", false, "Start lightweight web console")
	flag.StringVar(&hostFlag, "host", "127.0.0.1", "Host address for the web console to listen on")
	flag.IntVar(&portFlag, "port", 8080, "Port for the web console to listen on")
	flag.BoolVar(&helpFlag, "help", false, "Show this help message")
	flag.BoolVar(&helpFlag, "h", false, "Show this help message")

	// CI/CD flag binding
	flag.IntVar(&failScoreFlag, "fail-score", 0, "Fail if overall security score is less than this value (0-100)")
	flag.BoolVar(&failOnSharedNSFlag, "fail-on-shared-ns", false, "Fail if any namespace (mnt, pid, net, ipc, uts) is shared with host")
	flag.BoolVar(&failOnCapsFlag, "fail-on-caps", false, "Fail if any Critical or High risk capabilities are active")
	flag.BoolVar(&failOnMountRisksFlag, "fail-on-mount-risks", false, "Fail if any Critical, High, or Medium risk mounts are found")
	flag.BoolVar(&failOnSecretsFlag, "fail-on-secrets", false, "Fail if any sensitive environment secrets are found")
	flag.BoolVar(&failOnFDLeaksFlag, "fail-on-fd-leaks", false, "Fail if any high-risk leaked host file descriptors are found")
	flag.BoolVar(&failOnFSRisksFlag, "fail-on-fs-risks", false, "Fail if any Critical, High, or Medium filesystem risks are found")
	flag.BoolVar(&failOnRootFlag, "fail-on-root", false, "Fail if container is running as root on host (EUID=0 and not virtualized)")

	flag.Parse()

	if helpFlag {
		printUsage()
		os.Exit(0)
	}

	// 0. Handle Web Server
	if serverFlag {
		if err := server.Start(hostFlag, portFlag); err != nil {
			fmt.Fprintf(os.Stderr, "Error starting web server: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	// 1. Handle Listing
	if listFlag {
		listIsolated()
		os.Exit(0)
	}

	// 2. Resolve PID
	var targetPID int
	if pidFlag == "" {
		// If no PID is specified, scan for isolated processes and present them
		processes, err := auditor.FindIsolatedProcesses()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error scanning for isolated processes: %v\n", err)
			os.Exit(1)
		}

		if len(processes) == 0 {
			fmt.Printf("No running isolated processes (containers/sandboxes) detected.\n")
			fmt.Printf("To audit a specific process, run: %s --pid <PID>\n", os.Args[0])
			fmt.Printf("Or audit the auditor's own process: %s --pid %d\n", os.Args[0], os.Getpid())
			os.Exit(0)
		}

		fmt.Printf("No target PID specified. Running isolated processes found on this host:\n\n")
		printProcessTable(processes)
		fmt.Printf("\nTo audit a process from the list, run: %s --pid <PID>\n", os.Args[0])
		os.Exit(0)
	} else {
		pid, err := strconv.Atoi(pidFlag)
		if err != nil || pid <= 0 {
			fmt.Fprintf(os.Stderr, "Invalid PID: %s\n", pidFlag)
			os.Exit(1)
		}
		targetPID = pid
	}

	// 3. Verify PID exists
	if !util.ProcessExists(targetPID) {
		fmt.Fprintf(os.Stderr, "Process PID %d does not exist or is not accessible.\n", targetPID)
		os.Exit(1)
	}

	name, err := util.GetProcessName(targetPID)
	if err != nil {
		name = "unknown"
	}

	cmdline, _ := util.GetCmdline(targetPID)

	// 4. Generate Audit Report
	report, err := auditor.GenerateReport(targetPID, name, cmdline, maskFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Audit failed: %v\n", err)
		os.Exit(1)
	}

	// 5. Output Results
	if jsonFlag {
		jsonStr, err := report.RenderJSON()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to render JSON: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(jsonStr)
	} else if htmlFlag {
		htmlStr, err := report.RenderHTML()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to render HTML: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(htmlStr)
	} else {
		fmt.Println(report.RenderCLI())
	}

	// 6. CI/CD Assertions Check
	var failedAssertions []string

	if failScoreFlag > 0 && report.OverallScore < failScoreFlag {
		failedAssertions = append(failedAssertions, fmt.Sprintf("Overall security score %d is below required threshold of %d", report.OverallScore, failScoreFlag))
	}

	if failOnSharedNSFlag && report.Namespaces != nil {
		for _, ns := range report.Namespaces.Namespaces {
			if ns.IsSharedWithHost && ns.Name != "user" && ns.Name != "cgroup" && ns.Name != "time" {
				failedAssertions = append(failedAssertions, fmt.Sprintf("Namespace '%s' is shared with host", ns.Name))
			}
		}
	}

	if failOnCapsFlag && report.Capabilities != nil {
		for _, capRisk := range report.Capabilities.HighRiskCaps {
			if capRisk.RiskLevel == "Critical" || capRisk.RiskLevel == "High" {
				failedAssertions = append(failedAssertions, fmt.Sprintf("Active capability '%s' is high risk (%s)", capRisk.Name, capRisk.RiskLevel))
			}
		}
	}

	if failOnMountRisksFlag && report.Mounts != nil {
		for _, mountRisk := range report.Mounts.Risks {
			if mountRisk.RiskLevel == "Critical" || mountRisk.RiskLevel == "High" || mountRisk.RiskLevel == "Medium" {
				failedAssertions = append(failedAssertions, fmt.Sprintf("Mount exposure '%s -> %s' is high/medium risk (%s)", mountRisk.MountSource, mountRisk.MountPoint, mountRisk.RiskLevel))
			}
		}
	}

	if failOnSecretsFlag && report.Env != nil {
		if len(report.Env.Secrets) > 0 {
			failedAssertions = append(failedAssertions, fmt.Sprintf("Sensitive environment secret '%s' exposed", report.Env.Secrets[0].Key))
		}
	}

	if failOnFDLeaksFlag && report.FD != nil {
		for _, fd := range report.FD.FDs {
			if fd.IsHighRisk {
				failedAssertions = append(failedAssertions, fmt.Sprintf("High-risk leaked file descriptor found: fd %d pointing to %s (%s)", fd.FD, fd.Target, fd.Type))
			}
		}
	}

	if failOnFSRisksFlag && report.Filesystem != nil {
		for _, fsRisk := range report.Filesystem.Risks {
			if fsRisk.RiskLevel == "Critical" || fsRisk.RiskLevel == "High" || fsRisk.RiskLevel == "Medium" {
				failedAssertions = append(failedAssertions, fmt.Sprintf("Filesystem risk '%s' is high/medium risk (%s)", fsRisk.Path, fsRisk.RiskLevel))
			}
		}
	}

	if failOnRootFlag && report.Security != nil {
		if report.Security.EUID == 0 && !report.Security.UserNSMapped {
			failedAssertions = append(failedAssertions, "Container is running as root on host (EUID=0 and not virtualized)")
		}
	}

	if len(failedAssertions) > 0 {
		fmt.Fprintf(os.Stderr, "\n%s%s=== CI/CD AUDIT FAILED ===%s\n", auditor.Bold, auditor.Red, auditor.Reset)
		for _, assertion := range failedAssertions {
			fmt.Fprintf(os.Stderr, "  [✗] %s\n", assertion)
		}
		fmt.Fprintf(os.Stderr, "\n")
		os.Exit(1)
	}

	// If any CI/CD flags were passed and all checks succeeded
	if failScoreFlag > 0 || failOnSharedNSFlag || failOnCapsFlag || failOnMountRisksFlag || failOnSecretsFlag || failOnFDLeaksFlag || failOnFSRisksFlag || failOnRootFlag {
		fmt.Printf("\n%s%s=== CI/CD AUDIT SUCCESSFUL ===%s\n", auditor.Bold, auditor.Green, auditor.Reset)
		fmt.Printf("  [✓] All configured security assertions passed.\n\n")
	}
}

func listIsolated() {
	processes, err := auditor.FindIsolatedProcesses()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error scanning for isolated processes: %v\n", err)
		os.Exit(1)
	}

	if len(processes) == 0 {
		fmt.Println("No processes found running in isolated namespaces.")
		return
	}

	printProcessTable(processes)
}

func printProcessTable(processes []auditor.IsolatedProcess) {
	fmt.Printf("%s%-8s  %-20s  %-15s  %s%s\n", auditor.Bold, "PID", "NAME", "MOUNT NS INODE", "COMMAND LINE", auditor.Reset)
	fmt.Println(strings.Repeat("-", 80))
	for _, p := range processes {
		cmdStr := p.Cmdline
		if len(cmdStr) > 40 {
			cmdStr = cmdStr[:37] + "..."
		}
		fmt.Printf("%-8d  %-20s  %-15d  %s\n", p.PID, p.Name, p.MountInode, cmdStr)
	}
}
