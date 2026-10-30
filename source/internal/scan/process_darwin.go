//go:build darwin

package scan

import (
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var psLinePattern = regexp.MustCompile(`^\s*(\d+)\s+(\d+)\s+(\S+)\s+(.*)$`)

func listProcesses() ([]ProcessInfo, []Warning, error) {
	stdout, _, err := runCommand(15*time.Second, "ps", "-axo", "pid=,ppid=,user=,command=")
	if err != nil {
		return nil, nil, err
	}

	var processes []ProcessInfo
	for _, line := range strings.Split(string(stdout), "\n") {
		match := psLinePattern.FindStringSubmatch(line)
		if match == nil {
			continue
		}
		pid, _ := strconv.Atoi(match[1])
		ppid, _ := strconv.Atoi(match[2])
		command := match[4]
		name := command
		if fields := strings.Fields(command); len(fields) > 0 {
			name = filepath.Base(fields[0])
		}
		processes = append(processes, ProcessInfo{
			PID:     pid,
			PPID:    ppid,
			User:    match[3],
			Name:    name,
			Command: command,
		})
	}
	return processes, nil, nil
}
