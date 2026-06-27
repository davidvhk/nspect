package auditor

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"nspect/pkg/util"
)

// SocketInfo represents an active TCP socket connection or listening port.
type SocketInfo struct {
	Proto      string `json:"proto"` // tcp, tcp6
	LocalIP    string `json:"local_ip"`
	LocalPort  int    `json:"local_port"`
	RemoteIP   string `json:"remote_ip"`
	RemotePort int    `json:"remote_port"`
	State      string `json:"state"`
}

// NetAuditResult aggregates socket information within the namespace.
type NetAuditResult struct {
	ListeningPorts []SocketInfo `json:"listening_ports"`
	Connections    []SocketInfo `json:"connections"`
}

// TCP States
var tcpStates = map[string]string{
	"01": "ESTABLISHED",
	"02": "SYN_SENT",
	"03": "SYN_RECV",
	"04": "FIN_WAIT1",
	"05": "FIN_WAIT2",
	"06": "TIME_WAIT",
	"07": "CLOSE",
	"08": "CLOSE_WAIT",
	"09": "LAST_ACK",
	"0A": "LISTEN",
	"0B": "CLOSING",
}

// Decode IP and Port from procfs hex representation.
func decodeHexAddr(addr string, isIPv6 bool) (string, int, error) {
	parts := strings.Split(addr, ":")
	if len(parts) != 2 {
		return "", 0, fmt.Errorf("invalid hex address format: %s", addr)
	}

	hexIP := parts[0]
	hexPort := parts[1]

	port, err := strconv.ParseUint(hexPort, 16, 16)
	if err != nil {
		return "", 0, fmt.Errorf("failed to parse port: %w", err)
	}

	if isIPv6 {
		if len(hexIP) != 32 {
			return "", 0, fmt.Errorf("invalid IPv6 hex string: %s", hexIP)
		}
		var ipBytes [16]byte
		for i := 0; i < 4; i++ {
			wordHex := hexIP[i*8 : (i+1)*8]
			word, err := strconv.ParseUint(wordHex, 16, 32)
			if err != nil {
				return "", 0, fmt.Errorf("failed to parse IPv6 word: %w", err)
			}
			// Host-byte order (little-endian on x86)
			ipBytes[i*4] = byte(word)
			ipBytes[i*4+1] = byte(word >> 8)
			ipBytes[i*4+2] = byte(word >> 16)
			ipBytes[i*4+3] = byte(word >> 24)
		}
		return net.IP(ipBytes[:]).String(), int(port), nil
	}

	// IPv4 Address parsing
	ipVal, err := strconv.ParseUint(hexIP, 16, 32)
	if err != nil {
		return "", 0, fmt.Errorf("failed to parse IPv4 hex: %w", err)
	}
	ip := net.IPv4(byte(ipVal), byte(ipVal>>8), byte(ipVal>>16), byte(ipVal>>24))
	return ip.String(), int(port), nil
}

// ParseProcNetFile reads a /proc/[pid]/net/tcp or tcp6 file and returns sockets.
func ParseProcNetFile(filePath string, isIPv6 bool) ([]SocketInfo, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var sockets []SocketInfo
	scanner := bufio.NewScanner(file)
	
	// Skip header line
	if scanner.Scan() {
		_ = scanner.Text()
	}

	proto := "tcp"
	if isIPv6 {
		proto = "tcp6"
	}

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		localAddr := fields[1]
		remoteAddr := fields[2]
		stateHex := fields[3]

		localIP, localPort, err := decodeHexAddr(localAddr, isIPv6)
		if err != nil {
			continue
		}

		remoteIP, remotePort, err := decodeHexAddr(remoteAddr, isIPv6)
		if err != nil {
			continue
		}

		state, ok := tcpStates[stateHex]
		if !ok {
			state = "UNKNOWN"
		}

		sockets = append(sockets, SocketInfo{
			Proto:      proto,
			LocalIP:    localIP,
			LocalPort:  localPort,
			RemoteIP:   remoteIP,
			RemotePort: remotePort,
			State:      state,
		})
	}

	return sockets, scanner.Err()
}

// AuditNetwork extracts active ports and connections inside the process namespace.
func AuditNetwork(pid int) (*NetAuditResult, error) {
	var allSockets []SocketInfo

	// Parse IPv4 TCP
	tcp4Path := util.ProcPath(pid, "net", "tcp")
	if socks, err := ParseProcNetFile(tcp4Path, false); err == nil {
		allSockets = append(allSockets, socks...)
	}

	// Parse IPv6 TCP
	tcp6Path := util.ProcPath(pid, "net", "tcp6")
	if socks, err := ParseProcNetFile(tcp6Path, true); err == nil {
		allSockets = append(allSockets, socks...)
	}

	var listening []SocketInfo
	var conns []SocketInfo

	for _, s := range allSockets {
		if s.State == "LISTEN" {
			listening = append(listening, s)
		} else if s.State == "ESTABLISHED" {
			conns = append(conns, s)
		}
	}

	return &NetAuditResult{
		ListeningPorts: listening,
		Connections:    conns,
	}, nil
}
