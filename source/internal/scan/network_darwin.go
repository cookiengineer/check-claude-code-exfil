//go:build darwin

package scan

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"check-claude-code-exfil/internal/ioc"
)

func (s *scanner) scanNetwork() {
	stdout, _, err := runCommand(20*time.Second, "lsof", "-nP", "-iTCP", "-Fpcn")
	if len(stdout) > 0 {
		s.scanLsof(string(stdout))
		return
	}
	if err != nil && strings.TrimSpace(string(stdout)) == "" {
		stdout, stderr, netstatErr := runCommand(15*time.Second, "netstat", "-anv", "-p", "tcp")
		if netstatErr != nil || len(stdout) == 0 {
			stdout, stderr, netstatErr = runCommand(15*time.Second, "netstat", "-an")
			if netstatErr != nil {
				s.addWarning(Warning{
					Check:      "network",
					Message:    fmt.Sprintf("could not inspect TCP connections with lsof or netstat: %v: %s", netstatErr, strings.TrimSpace(string(stderr))),
					Incomplete: true,
				})
				return
			}
		}
		s.scanDarwinNetstat(string(stdout))
		return
	}
	s.scanDarwinNetstat("")
}

func (s *scanner) scanLsof(output string) {
	pid := 0
	command := ""
	for _, line := range strings.Split(output, "\n") {
		if line == "" {
			continue
		}
		switch line[0] {
		case 'p':
			pid, _ = strconv.Atoi(strings.TrimSpace(line[1:]))
		case 'c':
			command = strings.TrimSpace(line[1:])
		case 'n':
			name := strings.TrimSpace(line[1:])
			if name == "" {
				continue
			}
			if strings.Contains(name, ioc.TunnelServer) {
				s.addFinding(Finding{
					ID:       "network-tunnel-server",
					Severity: SeverityCritical,
					Category: "network",
					Title:    "Connection to attacker SSH tunnel server found",
					Detail:   "A TCP connection matches the attacker SSH tunnel server documented in the advisory.",
					PID:      pid,
					Process:  command,
					Address:  name,
					Evidence: "source=lsof",
				})
				continue
			}
			if isLsofLoopbackBeacon(name) {
				s.addFinding(Finding{
					ID:       "network-loopback-beacon",
					Severity: SeverityWarning,
					Category: "network",
					Title:    "Connection to local malware beacon port found",
					Detail:   "A TCP connection targets the loopback beacon port documented in the advisory. Verify whether another local service uses this port.",
					PID:      pid,
					Process:  command,
					Address:  name,
					Evidence: "source=lsof",
				})
			}
		}
	}
}

func isLsofLoopbackBeacon(name string) bool {
	index := strings.LastIndex(name, "->")
	if index < 0 {
		return false
	}
	host, port, ok := splitWindowsAddress(strings.TrimSpace(name[index+2:]))
	if !ok {
		return false
	}
	return isLoopbackHost(host) && port == strconv.Itoa(ioc.BeaconPort)
}

func (s *scanner) scanDarwinNetstat(output string) {
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 6 || !strings.HasPrefix(strings.ToLower(fields[0]), "tcp") {
			continue
		}
		local := fields[3]
		remote := fields[4]
		state := fields[5]
		if strings.Contains(line, ioc.TunnelServer) {
			s.addFinding(Finding{
				ID:       "network-tunnel-server",
				Severity: SeverityCritical,
				Category: "network",
				Title:    "Connection to attacker SSH tunnel server found",
				Detail:   "A TCP connection matches the attacker SSH tunnel server documented in the advisory.",
				Address:  local + " -> " + remote,
				Evidence: joinEvidence("state="+state, "source=netstat"),
			})
			continue
		}
		host, port, ok := parseBSDSockaddr(remote)
		if ok && isLoopbackHost(host) && port == strconv.Itoa(ioc.BeaconPort) {
			s.addFinding(Finding{
				ID:       "network-loopback-beacon",
				Severity: SeverityWarning,
				Category: "network",
				Title:    "Connection to local malware beacon port found",
				Detail:   "A TCP connection targets the loopback beacon port documented in the advisory. Verify whether another local service uses this port.",
				Address:  local + " -> " + remote,
				Evidence: joinEvidence("state="+state, "source=netstat"),
			})
		}
	}
}

func parseBSDSockaddr(value string) (host string, port string, ok bool) {
	index := strings.LastIndex(value, ".")
	if index < 0 || index == len(value)-1 {
		return "", "", false
	}
	host = strings.Trim(value[:index], "[]")
	port = value[index+1:]
	if host == "" || port == "" {
		return "", "", false
	}
	return host, port, true
}
