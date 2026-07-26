package auditor

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"

	"nspect/pkg/util"
)

// ProcessNode represents a single process in the hierarchy
type ProcessNode struct {
	PID             int            `json:"pid"`
	PPID            int            `json:"ppid"`
	Name            string         `json:"name"`
	Cmdline         string         `json:"cmdline"`
	UID             int            `json:"uid"`
	IsTarget        bool           `json:"is_target"`
	IsContainerRoot bool           `json:"is_container_root"`
	PIDNSInode      uint64         `json:"pid_ns_inode,omitempty"`
	Children        []*ProcessNode `json:"children,omitempty"`
}

// ProcessTreeAuditResult contains findings for process hierarchy
type ProcessTreeAuditResult struct {
	TargetPID     int            `json:"target_pid"`
	RootNode      *ProcessNode   `json:"root_node"`
	AncestorChain []*ProcessNode `json:"ancestor_chain"`
	TotalNodes    int            `json:"total_nodes"`
	TreeASCII     string         `json:"tree_ascii"`
}

// AuditProcessTree builds the process hierarchy tree for target PID
func AuditProcessTree(targetPID int) (*ProcessTreeAuditResult, error) {
	// Build map of all processes on host
	allProcs, parentMap := scanAllProcesses()

	targetNode, ok := allProcs[targetPID]
	if !ok {
		// Target process info from proc
		targetNode = fetchProcessNodeInfo(targetPID)
		if targetNode == nil {
			return nil, fmt.Errorf("process %d not found", targetPID)
		}
		allProcs[targetPID] = targetNode
	}
	targetNode.IsTarget = true

	// Build ancestor chain (target -> parent -> grandparent ... -> PID 1)
	var ancestors []*ProcessNode
	curr := targetNode
	for curr != nil {
		ancestors = append([]*ProcessNode{curr}, ancestors...)
		if curr.PPID <= 0 || curr.PPID == curr.PID {
			break
		}
		parent, ok := allProcs[curr.PPID]
		if !ok {
			parent = fetchProcessNodeInfo(curr.PPID)
			if parent != nil {
				allProcs[curr.PPID] = parent
			}
		}
		curr = parent
	}

	// Recursively attach children
	var attachChildren func(node *ProcessNode)
	totalNodes := 0
	attachChildren = func(node *ProcessNode) {
		totalNodes++
		childPIDs := parentMap[node.PID]
		for _, cPID := range childPIDs {
			if childNode, ok := allProcs[cPID]; ok {
				if childNode.PID == targetPID {
					childNode.IsTarget = true
				}
				node.Children = append(node.Children, childNode)
				attachChildren(childNode)
			}
		}
	}

	rootNode := ancestors[0]
	attachChildren(rootNode)

	// Format ASCII Tree representation
	var asciiBuilder strings.Builder
	buildASCIITree(&asciiBuilder, rootNode, "", true)

	return &ProcessTreeAuditResult{
		TargetPID:     targetPID,
		RootNode:      rootNode,
		AncestorChain: ancestors,
		TotalNodes:    totalNodes,
		TreeASCII:     asciiBuilder.String(),
	}, nil
}

// fetchProcessNodeInfo parses /proc/[pid]/status and /proc/[pid]/cmdline
func fetchProcessNodeInfo(pid int) *ProcessNode {
	statusPath := util.ProcPath(pid, "status")
	data, err := os.ReadFile(statusPath)
	if err != nil {
		return nil
	}

	node := &ProcessNode{PID: pid}
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			switch fields[0] {
			case "Name:":
				node.Name = fields[1]
			case "PPid:":
				node.PPID, _ = strconv.Atoi(fields[1])
			case "Uid:":
				node.UID, _ = strconv.Atoi(fields[1])
			}
		}
	}

	cmdBytes, err := os.ReadFile(util.ProcPath(pid, "cmdline"))
	if err == nil {
		node.Cmdline = strings.ReplaceAll(string(cmdBytes), "\x00", " ")
		node.Cmdline = strings.TrimSpace(node.Cmdline)
	}

	node.PIDNSInode = getNSInode(pid, "pid")

	// Check container root heuristics
	initNames := map[string]bool{"dumb-init": true, "tini": true, "s6-svscan": true, "systemd": true, "init": true, "entrypoint.sh": true}
	if initNames[node.Name] || node.PPID == 1 || (node.PID != 1 && node.PPID > 0 && isContainerShim(node.Name)) {
		node.IsContainerRoot = true
	}

	return node
}

func getNSInode(pid int, nsType string) uint64 {
	nsPath := util.ProcPath(pid, "ns", nsType)
	link, err := os.Readlink(nsPath)
	if err != nil {
		return 0
	}
	re := regexp.MustCompile(`\[(\d+)\]`)
	matches := re.FindStringSubmatch(link)
	if len(matches) > 1 {
		inode, _ := strconv.ParseUint(matches[1], 10, 64)
		return inode
	}
	return 0
}

func isContainerShim(name string) bool {
	n := strings.ToLower(name)
	return strings.Contains(n, "shim") || strings.Contains(n, "containerd") || strings.Contains(n, "podman") || strings.Contains(n, "docker")
}

// scanAllProcesses enumerates all numeric PIDs in /proc
func scanAllProcesses() (map[int]*ProcessNode, map[int][]int) {
	allProcs := make(map[int]*ProcessNode)
	parentMap := make(map[int][]int)

	entries, err := os.ReadDir("/proc")
	if err != nil {
		return allProcs, parentMap
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		node := fetchProcessNodeInfo(pid)
		if node != nil {
			allProcs[pid] = node
			parentMap[node.PPID] = append(parentMap[node.PPID], pid)
		}
	}

	return allProcs, parentMap
}

// buildASCIITree constructs an ASCII tree graph
func buildASCIITree(sb *strings.Builder, node *ProcessNode, prefix string, isLast bool) {
	marker := "├─ "
	if isLast {
		marker = "└─ "
	}

	tag := ""
	if node.IsTarget {
		tag = " [TARGET PROCESS]"
	} else if node.IsContainerRoot {
		tag = " [Container Init/Shim]"
	}

	cmd := node.Cmdline
	if len(cmd) > 50 {
		cmd = cmd[:47] + "..."
	}
	if cmd != "" {
		cmd = fmt.Sprintf(" (%s)", cmd)
	}

	sb.WriteString(fmt.Sprintf("%s%s%s (PID: %d, UID: %d)%s%s\n", prefix, marker, node.Name, node.PID, node.UID, cmd, tag))

	newPrefix := prefix
	if isLast {
		newPrefix += "   "
	} else {
		newPrefix += "│  "
	}

	for i, child := range node.Children {
		buildASCIITree(sb, child, newPrefix, i == len(node.Children)-1)
	}
}
