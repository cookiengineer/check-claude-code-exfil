//go:build windows

package scan

import (
	"fmt"
	"strings"
	"time"
)

const windowsProcessPowerShell = `Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name,CommandLine | ConvertTo-Json -Compress`

func listProcesses() ([]ProcessInfo, []Warning, error) {
	stdout, stderr, err := runCommand(20*time.Second, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", windowsProcessPowerShell)
	if err == nil {
		if processes, parseErr := parseWindowsProcessJSON(stdout); parseErr == nil {
			return processes, nil, nil
		}
	}
	powerShellErr := fmt.Errorf("powershell process query failed: %v: %s", err, strings.TrimSpace(string(stderr)))

	stdout, stderr, err = runCommand(20*time.Second, "wmic", "process", "get", "ProcessId,ParentProcessId,Name,CommandLine", "/FORMAT:CSV")
	if err == nil {
		if processes, parseErr := parseWMICProcessCSV(stdout); parseErr == nil {
			return processes, nil, nil
		}
	}
	wmicErr := fmt.Errorf("WMIC process query failed: %v: %s", err, strings.TrimSpace(string(stderr)))

	stdout, stderr, err = runCommand(10*time.Second, "tasklist", "/FO", "CSV", "/NH")
	if err == nil {
		processes, parseErr := parseTasklistCSV(stdout)
		if parseErr == nil {
			return processes, []Warning{{
				Check:      "process",
				Message:    "PowerShell and WMIC process command lines were unavailable; only process names were inspected",
				Incomplete: true,
			}}, nil
		}
	}

	return nil, nil, fmt.Errorf("%v; %v; tasklist failed: %v: %s", powerShellErr, wmicErr, err, strings.TrimSpace(string(stderr)))
}
