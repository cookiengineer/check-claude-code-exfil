//go:build windows

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

	if opts.AllUsers {
		homes, err := allUserHomes()
		if err != nil {
			warnings = append(warnings, Warning{
				Check:      "homes",
				Message:    fmt.Sprintf("could not enumerate all user profiles: %v", err),
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
				Message:    fmt.Sprintf("could not determine the current user's profile directory: %v", err),
				Incomplete: true,
			})
		} else {
			candidates = append(candidates, current)
		}
	}

	return validateHomeCandidates(candidates, explicit, &warnings), warnings
}

func allUserHomes() ([]string, error) {
	systemDrive := os.Getenv("SystemDrive")
	if systemDrive == "" {
		systemDrive = "C:"
	}
	usersDir := filepath.Join(systemDrive+string(os.PathSeparator), "Users")
	entries, err := os.ReadDir(usersDir)
	if err != nil {
		return nil, err
	}

	var homes []string
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		switch entry.Name() {
		case "Public", "Default", "Default User", "All Users":
			continue
		}
		homes = append(homes, filepath.Join(usersDir, entry.Name()))
	}

	if current, err := os.UserHomeDir(); err == nil {
		homes = append(homes, current)
	}
	sort.Strings(homes)
	return homes, nil
}

func tempDirsForHomes(homes []string) []string {
	candidates := []string{
		os.TempDir(),
		os.Getenv("TEMP"),
		os.Getenv("TMP"),
	}
	for _, home := range homes {
		candidates = append(candidates, filepath.Join(home, "AppData", "Local", "Temp"))
	}
	return existingDirs(candidates)
}
