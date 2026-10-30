//go:build !windows

package scan

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

func resolveHomes(opts Options) ([]string, []Warning) {
	var warnings []Warning
	var candidates []string
	explicit := len(opts.Homes) > 0

	if explicit {
		candidates = append(candidates, opts.Homes...)
	}

	autoAll := opts.AllUsers || (!explicit && isElevated())
	if autoAll {
		homes, err := allUserHomes()
		if err != nil {
			warnings = append(warnings, Warning{
				Check:      "homes",
				Message:    fmt.Sprintf("could not enumerate all user home directories: %v", err),
				Incomplete: true,
			})
		} else {
			candidates = append(candidates, homes...)
		}
	}

	if len(candidates) == 0 {
		current, err := os.UserHomeDir()
		if err != nil {
			warnings = append(warnings, Warning{
				Check:      "homes",
				Message:    fmt.Sprintf("could not determine the current user's home directory: %v", err),
				Incomplete: true,
			})
		} else {
			candidates = append(candidates, current)
		}
	}

	return validateHomeCandidates(candidates, explicit, &warnings), warnings
}

func allUserHomes() ([]string, error) {
	var homes []string
	for _, parent := range []string{"/home", "/Users"} {
		entries, err := os.ReadDir(parent)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, err
		}
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			switch entry.Name() {
			case "Shared", "lost+found", "Public", "Default", "Default User", "All Users":
				continue
			}
			homes = append(homes, filepath.Join(parent, entry.Name()))
		}
	}
	for _, rootHome := range []string{"/root", "/var/root"} {
		if info, err := os.Stat(rootHome); err == nil && info.IsDir() {
			homes = append(homes, rootHome)
		}
	}
	sort.Strings(homes)
	return homes, nil
}

func isElevated() bool {
	return os.Geteuid() == 0
}

func tempDirsForHomes(_ []string) []string {
	candidates := []string{
		os.TempDir(),
		os.Getenv("TMPDIR"),
		"/tmp",
		"/var/tmp",
		"/private/tmp",
	}
	if isElevated() {
		for _, pattern := range []string{"/var/folders/*/*/T", "/private/var/folders/*/*/T"} {
			matches, _ := filepath.Glob(pattern)
			candidates = append(candidates, matches...)
		}
	}
	return existingDirs(candidates)
}
