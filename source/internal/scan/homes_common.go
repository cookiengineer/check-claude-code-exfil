package scan

import (
	"fmt"
	"os"
	"path/filepath"
)

func validateHomeCandidates(candidates []string, required bool, warnings *[]Warning) []string {
	seen := make(map[string]struct{})
	var homes []string
	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}
		absolute, err := filepath.Abs(candidate)
		if err != nil {
			absolute = filepath.Clean(candidate)
		}
		info, err := os.Stat(absolute)
		if err != nil {
			if required {
				*warnings = append(*warnings, Warning{
					Check:      "homes",
					Path:       absolute,
					Message:    fmt.Sprintf("cannot inspect home directory: %v", err),
					Incomplete: true,
				})
			}
			continue
		}
		if !info.IsDir() {
			if required {
				*warnings = append(*warnings, Warning{
					Check:      "homes",
					Path:       absolute,
					Message:    "path is not a directory",
					Incomplete: true,
				})
			}
			continue
		}
		if _, ok := seen[absolute]; ok {
			continue
		}
		seen[absolute] = struct{}{}
		homes = append(homes, absolute)
	}
	return homes
}

func existingDirs(candidates []string) []string {
	seen := make(map[string]struct{})
	var dirs []string
	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}
		absolute, err := filepath.Abs(candidate)
		if err != nil {
			absolute = filepath.Clean(candidate)
		}
		if resolved, resolveErr := filepath.EvalSymlinks(absolute); resolveErr == nil {
			absolute = resolved
		}
		info, err := os.Stat(absolute)
		if err != nil || !info.IsDir() {
			continue
		}
		if _, ok := seen[absolute]; ok {
			continue
		}
		seen[absolute] = struct{}{}
		dirs = append(dirs, absolute)
	}
	return dirs
}
