package scan

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"check-claude-code-exfil/internal/ioc"
)

const maxExtensionWalkDepth = 3

type extensionPackage struct {
	Name      string `json:"name"`
	Publisher string `json:"publisher"`
	Version   string `json:"version"`
}

func (s *scanner) checkExtensions(home string) {
	for _, root := range extensionRoots(home) {
		entries, err := os.ReadDir(root)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			s.addWarning(Warning{
				Check:      "extensions",
				Path:       root,
				Message:    fmt.Sprintf("cannot read extension directory: %v", err),
				Incomplete: true,
			})
			continue
		}
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			dir := filepath.Join(root, entry.Name())
			s.checkExtensionDirectory(dir, entry.Name())
		}
	}
}

func (s *scanner) checkExtensionDirectory(dir, baseName string) {
	versionPrefix := strings.ToLower(ioc.ExtensionPublisher + "." + ioc.ExtensionName + "-" + ioc.ExtensionVersion)
	lowerBaseName := strings.ToLower(baseName)
	versionMatch := lowerBaseName == versionPrefix || strings.HasPrefix(lowerBaseName, versionPrefix+"-")
	if versionMatch {
		s.addFinding(Finding{
			ID:       "extension-vulnerable-version",
			Severity: SeverityCritical,
			Category: "extension",
			Title:    "Vulnerable Claude Code extension version installed",
			Detail:   "The installed extension version matches the compromised 2.1.313 release documented in the advisory.",
			Path:     dir,
			Evidence: "version=" + ioc.ExtensionVersion,
		})
	}

	packagePath := filepath.Join(dir, "package.json")
	if data, err := readFileLimited(packagePath, maxTextFileSize); err == nil {
		var pkg extensionPackage
		if json.Unmarshal(data, &pkg) == nil && !versionMatch {
			nameMatches := strings.EqualFold(pkg.Name, ioc.ExtensionName)
			publisherMatches := strings.EqualFold(pkg.Publisher, ioc.ExtensionPublisher) ||
				strings.HasPrefix(strings.ToLower(baseName), strings.ToLower(ioc.ExtensionPublisher+"."))
			if nameMatches && publisherMatches && pkg.Version == ioc.ExtensionVersion {
				s.addFinding(Finding{
					ID:       "extension-vulnerable-version",
					Severity: SeverityCritical,
					Category: "extension",
					Title:    "Vulnerable Claude Code extension version installed",
					Detail:   "The extension package metadata declares the compromised 2.1.313 release.",
					Path:     packagePath,
					Evidence: "version=" + pkg.Version,
				})
			}
		}
	} else if err != nil && !os.IsNotExist(err) && os.IsPermission(err) {
		s.addWarning(Warning{
			Check:      "extensions",
			Path:       packagePath,
			Message:    fmt.Sprintf("cannot read extension metadata: %v", err),
			Incomplete: true,
		})
	}

	s.scanExtensionBundle(dir)
}

func (s *scanner) scanExtensionBundle(dir string) {
	rootDepth := pathDepth(dir)
	_ = filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if entry.IsDir() {
			if path != dir && pathDepth(path)-rootDepth >= maxExtensionWalkDepth {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.EqualFold(entry.Name(), "extension.js") {
			return nil
		}
		info, statErr := entry.Info()
		if statErr != nil || info.Size() > 100<<20 {
			return nil
		}
		hash, hashErr := fileSHA256(path)
		if hashErr != nil || !strings.EqualFold(hash, ioc.ExtensionBundleSHA256) {
			return nil
		}
		s.addFinding(Finding{
			ID:       "extension-bundle-hash",
			Severity: SeverityCritical,
			Category: "extension",
			Title:    "Backdoored Claude Code extension bundle found",
			Detail:   "The extension.js SHA-256 hash matches the backdoored bundle documented in the advisory.",
			Path:     path,
			Evidence: "sha256=" + ioc.ExtensionBundleSHA256,
		})
		return nil
	})
}

func extensionRoots(home string) []string {
	known := []string{
		filepath.Join(home, ".vscode", "extensions"),
		filepath.Join(home, ".vscode-insiders", "extensions"),
		filepath.Join(home, ".vscode-oss", "extensions"),
		filepath.Join(home, ".vscode-server", "extensions"),
		filepath.Join(home, ".vscode-server-insiders", "extensions"),
		filepath.Join(home, ".cursor", "extensions"),
		filepath.Join(home, ".cursor-server", "extensions"),
		filepath.Join(home, ".windsurf", "extensions"),
		filepath.Join(home, ".windsurf-server", "extensions"),
		filepath.Join(home, ".positron", "extensions"),
		filepath.Join(home, ".trae", "extensions"),
		filepath.Join(home, ".kiro", "extensions"),
	}

	seen := make(map[string]struct{})
	var roots []string
	add := func(candidate string) {
		absolute, err := filepath.Abs(candidate)
		if err != nil {
			absolute = filepath.Clean(candidate)
		}
		if _, ok := seen[absolute]; ok {
			return
		}
		if info, err := os.Stat(absolute); err == nil && info.IsDir() {
			seen[absolute] = struct{}{}
			roots = append(roots, absolute)
		}
	}
	for _, candidate := range known {
		add(candidate)
	}

	entries, err := os.ReadDir(home)
	if err != nil {
		return roots
	}
	for _, entry := range entries {
		if !entry.IsDir() || !strings.HasPrefix(entry.Name(), ".") {
			continue
		}
		add(filepath.Join(home, entry.Name(), "extensions"))
	}
	return roots
}

func pathDepth(path string) int {
	clean := filepath.Clean(path)
	if clean == "." || clean == string(os.PathSeparator) {
		return 0
	}
	volume := filepath.VolumeName(clean)
	clean = strings.TrimPrefix(clean, volume)
	clean = strings.Trim(clean, string(os.PathSeparator))
	if clean == "" {
		return 0
	}
	return strings.Count(clean, string(os.PathSeparator)) + 1
}
