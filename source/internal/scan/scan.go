package scan

import (
	"fmt"
	"runtime"
	"strconv"
	"strings"
	"time"
)

type Options struct {
	Version        string
	Homes          []string
	AllUsers       bool
	IncludeProcess bool
	IncludeNetwork bool
	TempDirs       []string
}

type scanner struct {
	opts   Options
	report *Report
	seen   map[string]struct{}
}

func Run(opts Options) *Report {
	started := time.Now()
	report := &Report{
		Version:   opts.Version,
		Platform:  runtime.GOOS + "/" + runtime.GOARCH,
		StartedAt: started,
		Homes:     []string{},
		Findings:  []Finding{},
		Warnings:  []Warning{},
	}
	s := &scanner{
		opts:   opts,
		report: report,
		seen:   make(map[string]struct{}),
	}

	homes, warnings := resolveHomes(opts)
	for _, warning := range warnings {
		s.addWarning(warning)
	}
	report.Homes = homes
	if len(homes) == 0 {
		s.addWarning(Warning{
			Check:      "homes",
			Message:    "no home directories were available to scan",
			Incomplete: true,
		})
	}

	for _, home := range homes {
		s.scanHome(home)
	}

	tempDirs := opts.TempDirs
	if tempDirs == nil {
		tempDirs = tempDirsForHomes(homes)
	}
	s.scanTempDirs(tempDirs)

	s.checkGlobalPersistence()

	if opts.IncludeProcess {
		s.scanProcesses()
	}
	if opts.IncludeNetwork {
		s.scanNetwork()
	}

	report.Duration = time.Since(started)
	report.finalize()
	return report
}

func (s *scanner) scanHome(home string) {
	s.checkSSH(home)
	s.checkConfigArtifacts(home)
	s.checkExtensions(home)
	s.checkHomePersistence(home)
}

func (s *scanner) addFinding(f Finding) {
	key := strings.Join([]string{
		f.ID,
		f.Path,
		strconv.Itoa(f.Line),
		strconv.Itoa(f.PID),
		f.Address,
		f.Task,
		f.Fingerprint,
	}, "\x00")
	if _, ok := s.seen[key]; ok {
		return
	}
	s.seen[key] = struct{}{}
	s.report.Findings = append(s.report.Findings, f)
}

func (s *scanner) addWarning(w Warning) {
	key := strings.Join([]string{w.Check, w.Path, w.Message, fmt.Sprint(w.Incomplete)}, "\x00")
	if _, ok := s.seen["warning\x00"+key]; ok {
		return
	}
	s.seen["warning\x00"+key] = struct{}{}
	s.report.Warnings = append(s.report.Warnings, w)
}
