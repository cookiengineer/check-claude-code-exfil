package scan

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"time"
)

func (s *scanner) checkCronHome(home string) {
	username := filepath.Base(home)
	if home == "/root" || home == "/var/root" {
		username = "root"
	}
	if username == "" || username == "." || username == string(os.PathSeparator) {
		return
	}

	paths := []string{
		filepath.Join("/var/spool/cron/crontabs", username),
		filepath.Join("/var/spool/cron", username),
		filepath.Join("/var/at/tabs", username),
	}
	readAny := false
	for _, path := range paths {
		data, err := readFileLimited(path, maxTextFileSize)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			if os.IsPermission(err) {
				s.addWarning(Warning{
					Check:      "cron",
					Path:       path,
					Message:    fmt.Sprintf("cannot read user crontab: %v", err),
					Incomplete: true,
				})
			}
			continue
		}
		readAny = true
		s.checkCronContent(path, string(data))
	}

	if readAny || username != currentUsername() {
		return
	}

	stdout, _, err := runCommand(5*time.Second, "crontab", "-l")
	if err != nil {
		return
	}
	s.checkCronContent("crontab -l", string(stdout))
}

func (s *scanner) checkCronContent(path, content string) {
	for index, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		matches := matchedArtifactTokens(trimmed)
		if len(matches) == 0 {
			continue
		}
		s.addFinding(Finding{
			ID:       "cron-persistence",
			Severity: SeverityCritical,
			Category: "persistence",
			Title:    "Malware cron persistence entry found",
			Detail:   "The user crontab references an SSH backdoor or tunnel artifact.",
			Path:     path,
			Line:     index + 1,
			Evidence: "matched=" + strings.Join(matches, "|"),
		})
	}
}

func currentUsername() string {
	if current, err := user.Current(); err == nil {
		return current.Username
	}
	return os.Getenv("USER")
}
