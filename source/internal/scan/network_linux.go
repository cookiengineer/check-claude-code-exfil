//go:build linux

package scan

import (
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"check-claude-code-exfil/internal/ioc"
)

type procTCPConn struct {
	LocalHost  string
	LocalPort  string
	RemoteHost string
	RemotePort string
	State      string
	Inode      string
}

func (s *scanner) scanNetwork() {
	var matches []procTCPConn
	readAny := false
	for _, file := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		connections, err := readProcNet(file)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			s.addWarning(Warning{
				Check:      "network",
				Path:       file,
				Message:    fmt.Sprintf("cannot read kernel TCP table: %v", err),
				Incomplete: true,
			})
			continue
		}
		readAny = true
		for _, connection := range connections {
			if connection.RemoteHost == ioc.TunnelServer ||
				(isLoopbackHost(connection.RemoteHost) && connection.RemotePort == strconv.Itoa(ioc.BeaconPort)) {
				matches = append(matches, connection)
			}
		}
	}
	if !readAny {
		s.addWarning(Warning{
			Check:      "network",
			Message:    "no kernel TCP tables were available",
			Incomplete: true,
		})
		return
	}
	if len(matches) == 0 {
		return
	}

	inodes := make(map[string]struct{})
	for _, connection := range matches {
		inodes[connection.Inode] = struct{}{}
	}
	owners, names := socketOwners(inodes)

	for _, connection := range matches {
		pid := owners[connection.Inode]
		address := net.JoinHostPort(connection.RemoteHost, connection.RemotePort)
		state := tcpStateName(connection.State)
		evidence := joinEvidence("state="+state, "remote="+address)
		if pid > 0 {
			evidence = joinEvidence(evidence, "pid="+strconv.Itoa(pid))
		}

		if connection.RemoteHost == ioc.TunnelServer {
			s.addFinding(Finding{
				ID:       "network-tunnel-server",
				Severity: SeverityCritical,
				Category: "network",
				Title:    "Connection to attacker SSH tunnel server found",
				Detail:   "A TCP connection matches the attacker SSH tunnel server documented in the advisory.",
				PID:      pid,
				Process:  names[pid],
				Address:  address,
				Evidence: evidence,
			})
			continue
		}

		s.addFinding(Finding{
			ID:       "network-loopback-beacon",
			Severity: SeverityWarning,
			Category: "network",
			Title:    "Connection to local malware beacon port found",
			Detail:   "A TCP connection targets the loopback beacon port documented in the advisory. Verify whether another local service uses this port.",
			PID:      pid,
			Process:  names[pid],
			Address:  address,
			Evidence: evidence,
		})
	}
}

func readProcNet(path string) ([]procTCPConn, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var connections []procTCPConn
	for index, line := range strings.Split(string(data), "\n") {
		if index == 0 {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}
		localHost, localPort, localOK := parseProcAddress(fields[1])
		remoteHost, remotePort, remoteOK := parseProcAddress(fields[2])
		if !localOK || !remoteOK {
			continue
		}
		connections = append(connections, procTCPConn{
			LocalHost:  localHost,
			LocalPort:  localPort,
			RemoteHost: remoteHost,
			RemotePort: remotePort,
			State:      fields[3],
			Inode:      fields[9],
		})
	}
	return connections, nil
}

func parseProcAddress(value string) (host string, port string, ok bool) {
	parts := strings.Split(value, ":")
	if len(parts) != 2 {
		return "", "", false
	}
	raw, err := hex.DecodeString(parts[0])
	if err != nil {
		return "", "", false
	}
	portNumber, err := strconv.ParseUint(parts[1], 16, 16)
	if err != nil {
		return "", "", false
	}

	switch len(raw) {
	case 4:
		host = net.IPv4(raw[3], raw[2], raw[1], raw[0]).String()
	case 16:
		ordered := make([]byte, 16)
		for word := 0; word < 4; word++ {
			offset := word * 4
			ordered[offset] = raw[offset+3]
			ordered[offset+1] = raw[offset+2]
			ordered[offset+2] = raw[offset+1]
			ordered[offset+3] = raw[offset]
		}
		host = net.IP(ordered).String()
	default:
		return "", "", false
	}
	return host, strconv.Itoa(int(portNumber)), true
}

func socketOwners(inodes map[string]struct{}) (map[string]int, map[int]string) {
	owners := make(map[string]int)
	names := make(map[int]string)
	if len(inodes) == 0 {
		return owners, names
	}

	entries, err := os.ReadDir("/proc")
	if err != nil {
		return owners, names
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		fdDir := filepath.Join("/proc", entry.Name(), "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}
		for _, fd := range fds {
			target, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil || !strings.HasPrefix(target, "socket:[") || !strings.HasSuffix(target, "]") {
				continue
			}
			inode := target[len("socket:[") : len(target)-1]
			if _, ok := inodes[inode]; !ok {
				continue
			}
			owners[inode] = pid
			if name, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "comm")); err == nil {
				names[pid] = strings.TrimSpace(string(name))
			}
			break
		}
	}
	return owners, names
}

func tcpStateName(state string) string {
	switch strings.ToUpper(state) {
	case "01":
		return "ESTABLISHED"
	case "02":
		return "SYN_SENT"
	case "03":
		return "SYN_RECV"
	case "04":
		return "FIN_WAIT1"
	case "05":
		return "FIN_WAIT2"
	case "06":
		return "TIME_WAIT"
	case "07":
		return "CLOSE"
	case "08":
		return "CLOSE_WAIT"
	case "09":
		return "LAST_ACK"
	case "0A":
		return "LISTEN"
	case "0B":
		return "CLOSING"
	default:
		return state
	}
}
