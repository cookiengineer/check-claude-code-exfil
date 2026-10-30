//go:build linux

package scan

import (
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
)

func listProcesses() ([]ProcessInfo, []Warning, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, nil, err
	}

	users := make(map[string]string)
	var processes []ProcessInfo
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		cmdline, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "cmdline"))
		if err != nil {
			continue
		}
		command := strings.TrimSpace(strings.ReplaceAll(string(cmdline), "\x00", " "))
		if command == "" {
			continue
		}
		name, ppid, uid := readProcStatus(entry.Name())
		username := uid
		if cached, ok := users[uid]; ok {
			username = cached
		} else if current, lookupErr := user.LookupId(uid); lookupErr == nil {
			username = current.Username
			users[uid] = username
		}
		processes = append(processes, ProcessInfo{
			PID:     pid,
			PPID:    ppid,
			User:    username,
			Name:    name,
			Command: command,
		})
	}
	return processes, nil, nil
}

func readProcStatus(pid string) (name string, ppid int, uid string) {
	data, err := os.ReadFile(filepath.Join("/proc", pid, "status"))
	if err != nil {
		return "", 0, ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		switch fields[0] {
		case "Name:":
			name = fields[1]
		case "PPid:":
			ppid, _ = strconv.Atoi(fields[1])
		case "Uid:":
			uid = fields[1]
		}
	}
	return name, ppid, uid
}
