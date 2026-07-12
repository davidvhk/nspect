package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"

	"nspect/pkg/auditor"
	"nspect/pkg/util"
)

func printUsage() {
	fmt.Printf("Linux Capability & Namespace Auditor (nspect)\n")
	fmt.Printf("Usage: %s [flags]\n\n", os.Args[0])
	fmt.Printf("Flags:\n")
	fmt.Printf("  -p, --pid <PID>   Audit the specified process ID\n")
	fmt.Printf("  -l, --list        List all running processes in isolated namespaces (containers/sandboxes)\n")
	fmt.Printf("  -m, --mask        Mask sensitive environment variables instead of showing them in plaintext\n")
	fmt.Printf("  -j, --json        Output report in JSON format\n")
	fmt.Printf("  -H, --html        Output report in HTML format\n")
	fmt.Printf("  -h, --help        Show this help message\n")
}

func main() {
	var pidFlag string
	var listFlag bool
	var maskFlag bool
	var jsonFlag bool
	var htmlFlag bool
	var helpFlag bool

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
	flag.BoolVar(&helpFlag, "help", false, "Show this help message")
	flag.BoolVar(&helpFlag, "h", false, "Show this help message")

	flag.Parse()

	if helpFlag {
		printUsage()
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
