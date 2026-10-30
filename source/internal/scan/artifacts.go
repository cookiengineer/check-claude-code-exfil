package scan

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"check-claude-code-exfil/internal/ioc"
)

var tempKeyPattern = regexp.MustCompile(`(?i)^\.stk_[0-9a-f]{10}$`)

type artifactSpec struct {
	Path     string
	ID       string
	Category string
	Title    string
	Detail   string
}

func (s *scanner) checkConfigArtifacts(home string) {
	configDir := filepath.Join(home, ".config")
	specs := []artifactSpec{
		{
			Path:     filepath.Join(configDir, ".smt"),
			ID:       "persistence-script-smt",
			Category: "persistence",
			Title:    "Malware persistence script found",
			Detail:   "The hidden .smt script is used to recreate the tunnel key and restart the SSH tunnel.",
		},
		{
			Path:     filepath.Join(configDir, ".smtk"),
			ID:       "tunnel-key-smtk",
			Category: "ssh",
			Title:    "Malware tunnel private key found",
			Detail:   "The .smtk file is used as the identity for the reverse SSH tunnel.",
		},
		{
			Path:     filepath.Join(configDir, "smt.cmd"),
			ID:       "windows-persistence-script",
			Category: "persistence",
			Title:    "Windows malware persistence script found",
			Detail:   "The smt.cmd script matches the Windows persistence artifact documented in the advisory.",
		},
		{
			Path:     filepath.Join(configDir, "smtk"),
			ID:       "windows-tunnel-key",
			Category: "ssh",
			Title:    "Windows malware tunnel private key found",
			Detail:   "The smtk file matches the Windows tunnel key artifact documented in the advisory.",
		},
	}

	for _, spec := range specs {
		exists, err := pathExists(spec.Path)
		if err != nil {
			s.addWarning(Warning{
				Check:      spec.Category,
				Path:       spec.Path,
				Message:    fmt.Sprintf("cannot inspect path: %v", err),
				Incomplete: true,
			})
			continue
		}
		if !exists {
			continue
		}

		finding := Finding{
			ID:       spec.ID,
			Severity: SeverityCritical,
			Category: spec.Category,
			Title:    spec.Title,
			Detail:   spec.Detail,
			Path:     spec.Path,
		}

		inspection, inspectErr := inspectKeyFile(spec.Path)
		if inspectErr != nil {
			if !strings.Contains(inspectErr.Error(), "larger than") {
				finding.Evidence = joinEvidence(finding.Evidence, "content could not be inspected")
			}
		} else {
			finding.Fingerprint = inspection.Fingerprint
			if len(inspection.MatchedTokens) > 0 {
				finding.Evidence = joinEvidence(finding.Evidence, "matched="+strings.Join(inspection.MatchedTokens, "|"))
			}
		}
		s.addFinding(finding)
		s.addInspectionFindings(spec.Path, inspection, spec.Category)
	}
}

func (s *scanner) scanTempDirs(dirs []string) {
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			if os.IsPermission(err) {
				s.addWarning(Warning{
					Check:      "temp",
					Path:       dir,
					Message:    fmt.Sprintf("cannot read temporary directory: %v", err),
					Incomplete: true,
				})
			}
			continue
		}
		for _, entry := range entries {
			name := entry.Name()
			if !strings.HasPrefix(strings.ToLower(name), ".stk_") {
				continue
			}
			path := filepath.Join(dir, name)
			info, statErr := os.Stat(path)
			if statErr != nil || !info.Mode().IsRegular() {
				continue
			}
			if !tempKeyPattern.MatchString(name) {
				s.addFinding(Finding{
					ID:       "temp-tunnel-key-unexpected",
					Severity: SeverityWarning,
					Category: "ssh",
					Title:    "Unexpected .stk_ tunnel key file found",
					Detail:   "The filename uses the malware prefix but does not match the expected 10-character MD5 suffix.",
					Path:     path,
				})
				continue
			}

			finding := Finding{
				ID:       "temp-tunnel-key",
				Severity: SeverityCritical,
				Category: "ssh",
				Title:    "Embedded tunnel private key found in temporary directory",
				Detail:   "The .stk_ file matches the initial tunnel private-key artifact documented in the advisory.",
				Path:     path,
			}
			inspection, inspectErr := inspectKeyFile(path)
			if inspectErr == nil {
				finding.Fingerprint = inspection.Fingerprint
				if len(inspection.MatchedTokens) > 0 {
					finding.Evidence = "matched=" + strings.Join(inspection.MatchedTokens, "|")
				}
			}
			s.addFinding(finding)
			s.addInspectionFindings(path, inspection, "ssh")
		}
	}
}

func (s *scanner) addInspectionFindings(path string, inspection keyFileInspection, category string) {
	if inspection.TunnelFingerprint {
		s.addFinding(Finding{
			ID:          "tunnel-key-fingerprint",
			Severity:    SeverityCritical,
			Category:    category,
			Title:       "Attacker tunnel private key fingerprint found",
			Detail:      "The embedded private key's public-key fingerprint matches the tunnel key documented in the advisory.",
			Path:        path,
			Fingerprint: inspection.Fingerprint,
			Evidence:    "fingerprint=" + ioc.TunnelKeyFingerprint,
		})
	}
	if inspection.VictimFingerprint {
		s.addFinding(Finding{
			ID:          "victim-key-fingerprint",
			Severity:    SeverityCritical,
			Category:    "ssh",
			Title:       "Attacker victim-login key fingerprint found",
			Detail:      "The key's public-key fingerprint matches the key planted in authorized_keys.",
			Path:        path,
			Fingerprint: inspection.Fingerprint,
			Evidence:    "fingerprint=" + ioc.VictimKeyFingerprint,
		})
	}
	if inspection.TunnelComment {
		s.addFinding(Finding{
			ID:       "tunnel-key-comment",
			Severity: SeverityWarning,
			Category: category,
			Title:    "Attacker tunnel key comment found",
			Detail:   "The file references the svc-telemetry-tun key comment documented in the advisory.",
			Path:     path,
			Evidence: "comment=" + ioc.TunnelKeyComment,
		})
	}
}
