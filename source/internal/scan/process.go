package scan

import (
	"fmt"
	"strings"
)

type ProcessInfo struct {
	PID     int
	PPID    int
	User    string
	Name    string
	Command string
}

func (s *scanner) scanProcesses() {
	processes, warnings, err := listProcesses()
	for _, warning := range warnings {
		s.addWarning(warning)
	}
	if err != nil {
		s.addWarning(Warning{
			Check:      "process",
			Message:    fmt.Sprintf("could not enumerate processes: %v", err),
			Incomplete: true,
		})
		return
	}

	for _, process := range processes {
		reasons := processReasons(process.Command)
		if len(reasons) == 0 {
			continue
		}
		s.addFinding(Finding{
			ID:       "process-ioc",
			Severity: SeverityCritical,
			Category: "process",
			Title:    "Process referencing malware SSH backdoor artifacts",
			Detail:   "The running process command line references an indicator documented in the advisory.",
			PID:      process.PID,
			PPID:     process.PPID,
			Process:  process.Name,
			Evidence: "matched=" + strings.Join(reasons, "|"),
		})
	}
}

func processReasons(command string) []string {
	if strings.TrimSpace(command) == "" {
		return nil
	}
	lower := strings.ToLower(command)
	reasons := matchedArtifactTokens(command)
	if strings.Contains(lower, "smtk") && !strings.Contains(lower, ".smtk") {
		reasons = append(reasons, "smtk")
	}
	return uniqueStrings(reasons)
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{})
	var result []string
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}
