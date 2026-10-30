package scan

import (
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
)

func (r *Report) WriteText(w io.Writer, verbose bool) {
	fmt.Fprintf(w, "check-claude-code-exfil %s\n", r.Version)
	fmt.Fprintf(w, "Platform: %s\n", r.Platform)
	fmt.Fprintf(w, "Duration: %s\n", r.Duration.Round(1_000_000))
	if len(r.Homes) > 0 {
		fmt.Fprintf(w, "Scanning: %s\n", strings.Join(r.Homes, ", "))
	}
	fmt.Fprintln(w)

	if len(r.Findings) == 0 {
		fmt.Fprintln(w, "No indicators of compromise found.")
	} else {
		fmt.Fprintf(w, "Findings (%d):\n", len(r.Findings))
		for _, finding := range r.Findings {
			fmt.Fprintf(w, "[%s] %s\n", strings.ToUpper(string(finding.Severity)), finding.Title)
			fmt.Fprintf(w, "  id: %s\n", finding.ID)
			fmt.Fprintf(w, "  category: %s\n", finding.Category)
			if finding.Path != "" {
				location := finding.Path
				if finding.Line > 0 {
					location += ":" + strconv.Itoa(finding.Line)
				}
				fmt.Fprintf(w, "  path: %s\n", location)
			}
			if finding.PID > 0 {
				fmt.Fprintf(w, "  pid: %d\n", finding.PID)
			}
			if finding.PPID > 0 {
				fmt.Fprintf(w, "  ppid: %d\n", finding.PPID)
			}
			if finding.Process != "" {
				fmt.Fprintf(w, "  process: %s\n", finding.Process)
			}
			if finding.Address != "" {
				fmt.Fprintf(w, "  address: %s\n", finding.Address)
			}
			if finding.Task != "" {
				fmt.Fprintf(w, "  task: %s\n", finding.Task)
			}
			if finding.Fingerprint != "" {
				fmt.Fprintf(w, "  fingerprint: %s\n", finding.Fingerprint)
			}
			if finding.Evidence != "" {
				fmt.Fprintf(w, "  evidence: %s\n", finding.Evidence)
			}
			if finding.Detail != "" {
				fmt.Fprintf(w, "  detail: %s\n", finding.Detail)
			}
			fmt.Fprintln(w)
		}
	}

	if len(r.Warnings) > 0 {
		if verbose || hasIncompleteWarning(r.Warnings) {
			fmt.Fprintf(w, "Warnings (%d):\n", len(r.Warnings))
			for _, warning := range r.Warnings {
				fmt.Fprintf(w, "- %s: %s", warning.Check, warning.Message)
				if warning.Path != "" {
					fmt.Fprintf(w, " (%s)", warning.Path)
				}
				if warning.Incomplete {
					fmt.Fprint(w, " [incomplete]")
				}
				fmt.Fprintln(w)
			}
			fmt.Fprintln(w)
		} else {
			fmt.Fprintf(w, "Warnings: %d (use --verbose to show)\n\n", len(r.Warnings))
		}
	}

	fmt.Fprintf(w, "Summary: %d critical, %d warning, %d info\n",
		r.Count(SeverityCritical), r.Count(SeverityWarning), r.Count(SeverityInfo))

	switch r.ExitCode {
	case 1:
		fmt.Fprintln(w, "Result: AFFECTED - indicators of compromise were found.")
	case 2:
		fmt.Fprintln(w, "Result: INCOMPLETE - no indicators found, but parts of the scan could not be completed.")
	default:
		fmt.Fprintln(w, "Result: CLEAN - no indicators of compromise found.")
	}
}

func (r *Report) WriteJSON(w io.Writer) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(r)
}
