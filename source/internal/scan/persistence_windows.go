//go:build windows

package scan

import (
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func (s *scanner) checkHomePersistence(home string) {
	startup := filepath.Join(home, "AppData", "Roaming", "Microsoft", "Windows", "Start Menu", "Programs", "Startup")
	s.checkStartupDir(startup)
	if appData := os.Getenv("APPDATA"); appData != "" {
		s.checkStartupDir(filepath.Join(appData, "Microsoft", "Windows", "Start Menu", "Programs", "Startup"))
	}
}

func (s *scanner) checkGlobalPersistence() {
	s.checkScheduledTasks()
	if programData := os.Getenv("ProgramData"); programData != "" {
		s.checkStartupDir(filepath.Join(programData, "Microsoft", "Windows", "Start Menu", "Programs", "Startup"))
	}
}

func (s *scanner) checkStartupDir(dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return
		}
		if os.IsPermission(err) {
			s.addWarning(Warning{
				Check:      "startup",
				Path:       dir,
				Message:    fmt.Sprintf("cannot read Startup folder: %v", err),
				Incomplete: true,
			})
		}
		return
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		if strings.EqualFold(entry.Name(), "sysmon.cmd") {
			s.addFinding(Finding{
				ID:       "windows-startup-sysmon",
				Severity: SeverityCritical,
				Category: "persistence",
				Title:    "Malware Startup folder persistence script found",
				Detail:   "The sysmon.cmd Startup-folder script matches the Windows fallback persistence artifact.",
				Path:     path,
			})
			continue
		}

		data, readErr := readFileLimited(path, maxTextFileSize)
		if readErr != nil {
			if os.IsPermission(readErr) {
				s.addWarning(Warning{
					Check:      "startup",
					Path:       path,
					Message:    fmt.Sprintf("cannot read Startup-folder file: %v", readErr),
					Incomplete: true,
				})
			}
			continue
		}
		matches := matchedArtifactTokens(string(data))
		if len(matches) == 0 {
			continue
		}
		s.addFinding(Finding{
			ID:       "windows-startup-ioc",
			Severity: SeverityCritical,
			Category: "persistence",
			Title:    "Startup-folder file references malware artifacts",
			Detail:   "The Startup-folder entry references the SSH backdoor or tunnel persistence artifacts.",
			Path:     path,
			Evidence: "matched=" + strings.Join(matches, "|"),
		})
	}
}

func (s *scanner) checkScheduledTasks() {
	stdout, stderr, err := runCommand(15*time.Second, "schtasks", "/Query", "/TN", "SysMon", "/XML")
	if err == nil && len(stdout) > 0 {
		matches := matchedArtifactTokens(string(stdout))
		s.addFinding(Finding{
			ID:       "windows-scheduled-task-sysmon",
			Severity: SeverityCritical,
			Category: "persistence",
			Title:    "Malware SysMon scheduled task found",
			Detail:   "The Windows scheduled task named SysMon matches the persistence artifact documented in the advisory.",
			Path:     "schtasks:SysMon",
			Task:     "SysMon",
			Evidence: "matched=" + strings.Join(matches, "|"),
		})
	} else if err != nil {
		combined := strings.ToLower(string(stdout) + string(stderr))
		if strings.Contains(combined, "access is denied") ||
			strings.Contains(combined, "access denied") ||
			strings.Contains(combined, "permission") {
			s.addWarning(Warning{
				Check:      "schtasks",
				Path:       "SysMon",
				Message:    "cannot query the SysMon scheduled task due to insufficient privileges",
				Incomplete: true,
			})
		}
	}

	stdout, stderr, err = runCommand(30*time.Second, "schtasks", "/Query", "/FO", "CSV", "/V")
	if err != nil {
		combined := strings.ToLower(string(stdout) + string(stderr))
		if !strings.Contains(combined, "access denied") && !strings.Contains(combined, "access is denied") {
			s.addWarning(Warning{
				Check:      "schtasks",
				Message:    fmt.Sprintf("could not enumerate all scheduled tasks: %v", err),
				Incomplete: true,
			})
		}
		if len(stdout) == 0 {
			return
		}
	}

	reader := csv.NewReader(strings.NewReader(string(stdout)))
	reader.FieldsPerRecord = -1
	reader.LazyQuotes = true
	records, parseErr := reader.ReadAll()
	if parseErr != nil {
		s.addWarning(Warning{
			Check:      "schtasks",
			Message:    fmt.Sprintf("could not parse scheduled task output: %v", parseErr),
			Incomplete: true,
		})
		return
	}

	for index, record := range records {
		if index == 0 || len(record) == 0 {
			continue
		}
		matches := matchedArtifactTokens(strings.Join(record, " "))
		if len(matches) == 0 {
			continue
		}
		taskName := record[0]
		id := "windows-scheduled-task-ioc"
		path := "schtasks:" + taskName
		if strings.EqualFold(taskName, "SysMon") {
			id = "windows-scheduled-task-sysmon"
			path = "schtasks:SysMon"
		}
		s.addFinding(Finding{
			ID:       id,
			Severity: SeverityCritical,
			Category: "persistence",
			Title:    "Scheduled task references malware artifacts",
			Detail:   "The scheduled task references the SSH backdoor or tunnel persistence artifacts.",
			Path:     path,
			Task:     taskName,
			Evidence: "matched=" + strings.Join(matches, "|"),
		})
	}
}
