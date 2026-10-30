//go:build darwin

package scan

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"check-claude-code-exfil/internal/ioc"
)

const launchAgentFileName = "com.apple.sysmond.plist"

func (s *scanner) checkHomePersistence(home string) {
	s.checkLaunchAgents(home)
	s.checkCronHome(home)
}

func (s *scanner) checkLaunchAgents(home string) {
	dir := filepath.Join(home, "Library", "LaunchAgents")
	exactPath := filepath.Join(dir, launchAgentFileName)
	if exists, err := pathExists(exactPath); err != nil {
		s.addWarning(Warning{
			Check:      "launchagent",
			Path:       exactPath,
			Message:    fmt.Sprintf("cannot inspect LaunchAgent: %v", err),
			Incomplete: true,
		})
	} else if exists {
		finding := Finding{
			ID:       "macos-launchagent-sysmond",
			Severity: SeverityCritical,
			Category: "persistence",
			Title:    "Malware LaunchAgent persistence file found",
			Detail:   "The plist masquerades as com.apple.sysmond and is used to run the hidden .smt tunnel script.",
			Path:     exactPath,
		}
		if data, readErr := readFileLimited(exactPath, maxTextFileSize); readErr == nil {
			matches := matchedArtifactTokens(string(data))
			if containsFold(string(data), "/bin/sh") {
				matches = append(matches, "/bin/sh")
			}
			if len(matches) > 0 {
				finding.Evidence = "matched=" + strings.Join(matches, "|")
			}
		}
		s.addFinding(finding)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return
		}
		s.addWarning(Warning{
			Check:      "launchagent",
			Path:       dir,
			Message:    fmt.Sprintf("cannot read LaunchAgents directory: %v", err),
			Incomplete: true,
		})
		return
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(strings.ToLower(entry.Name()), ".plist") {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		if path == exactPath {
			continue
		}
		data, readErr := readFileLimited(path, maxTextFileSize)
		if readErr != nil {
			if os.IsPermission(readErr) {
				s.addWarning(Warning{
					Check:      "launchagent",
					Path:       path,
					Message:    fmt.Sprintf("cannot read LaunchAgent: %v", readErr),
					Incomplete: true,
				})
			}
			continue
		}
		content := string(data)
		if !containsFold(content, launchAgentFileName) &&
			!containsFold(content, ".config/.smt") &&
			!containsFold(content, ".config\\.smt") &&
			!containsFold(content, ".smtk") {
			continue
		}
		s.addFinding(Finding{
			ID:       "macos-launchagent-ioc",
			Severity: SeverityCritical,
			Category: "persistence",
			Title:    "LaunchAgent references malware persistence artifacts",
			Detail:   "The plist references the com.apple.sysmond label or the hidden .smt tunnel script.",
			Path:     path,
			Evidence: "matched=" + strings.Join(matchedArtifactTokens(content), "|"),
		})
	}
}

func (s *scanner) checkGlobalPersistence() {
	stdout, _, err := runCommand(10*time.Second, "launchctl", "list")
	if err != nil {
		return
	}
	if containsFold(string(stdout), launchAgentFileName) || containsFold(string(stdout), ioc.VictimKeyComment) {
		s.addFinding(Finding{
			ID:       "macos-launchctl-sysmond",
			Severity: SeverityCritical,
			Category: "persistence",
			Title:    "Malware LaunchAgent is loaded in launchctl",
			Detail:   "launchctl reports the com.apple.sysmond label used by the malware.",
			Path:     "launchctl",
			Task:     launchAgentFileName,
			Evidence: "loaded=" + launchAgentFileName,
		})
	}
}
