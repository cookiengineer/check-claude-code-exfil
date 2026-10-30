//go:build windows

package scan

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"check-claude-code-exfil/internal/ioc"
)

func (s *scanner) scanNetwork() {
	stdout, stderr, err := runCommand(15*time.Second, "netstat", "-ano", "-p", "TCP")
	if err != nil || len(stdout) == 0 {
		stdout, stderr, err = runCommand(15*time.Second, "netstat", "-ano")
	}
	if err != nil {
		s.addWarning(Warning{
			Check:      "network",
			Message:    fmt.Sprintf("could not inspect TCP connections with netstat: %v: %s", err, strings.TrimSpace(string(stderr))),
			Incomplete: true,
		})
		return
	}

	for _, connection := range parseWindowsNetstat(string(stdout)) {
		remoteHost, remotePort, ok := splitWindowsAddress(connection.Remote)
		if !ok {
			continue
		}
		address := connection.Local + " -> " + connection.Remote
		evidence := "state=" + connection.State
		if connection.PID > 0 {
			evidence = joinEvidence(evidence, "pid="+strconv.Itoa(connection.PID))
		}

		if remoteHost == ioc.TunnelServer {
			s.addFinding(Finding{
				ID:       "network-tunnel-server",
				Severity: SeverityCritical,
				Category: "network",
				Title:    "Connection to attacker SSH tunnel server found",
				Detail:   "A TCP connection matches the attacker SSH tunnel server documented in the advisory.",
				PID:      connection.PID,
				Address:  address,
				Evidence: evidence,
			})
			continue
		}
		if isLoopbackHost(remoteHost) && remotePort == strconv.Itoa(ioc.BeaconPort) {
			s.addFinding(Finding{
				ID:       "network-loopback-beacon",
				Severity: SeverityWarning,
				Category: "network",
				Title:    "Connection to local malware beacon port found",
				Detail:   "A TCP connection targets the loopback beacon port documented in the advisory. Verify whether another local service uses this port.",
				PID:      connection.PID,
				Address:  address,
				Evidence: evidence,
			})
		}
	}
}
