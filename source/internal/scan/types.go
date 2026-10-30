package scan

import (
	"sort"
	"time"
)

type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityWarning  Severity = "warning"
	SeverityInfo     Severity = "info"
)

type Finding struct {
	ID          string   `json:"id"`
	Severity    Severity `json:"severity"`
	Category    string   `json:"category"`
	Title       string   `json:"title"`
	Detail      string   `json:"detail,omitempty"`
	Path        string   `json:"path,omitempty"`
	Line        int      `json:"line,omitempty"`
	PID         int      `json:"pid,omitempty"`
	PPID        int      `json:"ppid,omitempty"`
	Process     string   `json:"process,omitempty"`
	Address     string   `json:"address,omitempty"`
	Task        string   `json:"task,omitempty"`
	Fingerprint string   `json:"fingerprint,omitempty"`
	Evidence    string   `json:"evidence,omitempty"`
}

type Warning struct {
	Check      string `json:"check"`
	Path       string `json:"path,omitempty"`
	Message    string `json:"message"`
	Incomplete bool   `json:"incomplete"`
}

type Report struct {
	Version    string        `json:"version"`
	Platform   string        `json:"platform"`
	StartedAt  time.Time     `json:"started_at"`
	DurationMS int64         `json:"duration_ms"`
	Homes      []string      `json:"homes"`
	Findings   []Finding     `json:"findings"`
	Warnings   []Warning     `json:"warnings"`
	Affected   bool          `json:"affected"`
	ExitCode   int           `json:"exit_code"`
	Duration   time.Duration `json:"-"`
}

func (r *Report) finalize() {
	rank := map[Severity]int{
		SeverityCritical: 0,
		SeverityWarning:  1,
		SeverityInfo:     2,
	}
	sort.SliceStable(r.Findings, func(i, j int) bool {
		a, b := r.Findings[i], r.Findings[j]
		if rank[a.Severity] != rank[b.Severity] {
			return rank[a.Severity] < rank[b.Severity]
		}
		if a.Category != b.Category {
			return a.Category < b.Category
		}
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		if a.PID != b.PID {
			return a.PID < b.PID
		}
		if a.Address != b.Address {
			return a.Address < b.Address
		}
		return a.Title < b.Title
	})

	r.Affected = len(r.Findings) > 0
	r.DurationMS = r.Duration.Milliseconds()
	switch {
	case r.Affected:
		r.ExitCode = 1
	case hasIncompleteWarning(r.Warnings):
		r.ExitCode = 2
	default:
		r.ExitCode = 0
	}
}

func hasIncompleteWarning(warnings []Warning) bool {
	for _, warning := range warnings {
		if warning.Incomplete {
			return true
		}
	}
	return false
}

func (r *Report) Count(severity Severity) int {
	count := 0
	for _, finding := range r.Findings {
		if finding.Severity == severity {
			count++
		}
	}
	return count
}
