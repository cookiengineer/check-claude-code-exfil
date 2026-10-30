package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"check-claude-code-exfil/internal/scan"
)

const version = "0.1.0"

type stringList []string

func (s *stringList) String() string {
	return strings.Join(*s, ",")
}

func (s *stringList) Set(value string) error {
	*s = append(*s, value)
	return nil
}

func main() {
	var homes stringList
	allUsers := flag.Bool("all-users", false, "scan every local user home/profile")
	jsonOutput := flag.Bool("json", false, "write a JSON report")
	verbose := flag.Bool("verbose", false, "show warnings and additional scan details")
	noProcess := flag.Bool("no-process", false, "skip live process inspection")
	noNetwork := flag.Bool("no-network", false, "skip live network inspection")
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Var(&homes, "home", "scan a specific home directory or profile (repeatable)")

	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage: %s [flags]\n\n", os.Args[0])
		fmt.Fprintf(flag.CommandLine.Output(), "Checks macOS, Linux, and Windows systems for indicators of compromise from the Claude Code extension compromise advisory.\n\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	if *showVersion {
		fmt.Printf("check-claude-code-exfil %s\n", version)
		return
	}

	report := scan.Run(scan.Options{
		Version:        version,
		Homes:          homes,
		AllUsers:       *allUsers,
		IncludeProcess: !*noProcess,
		IncludeNetwork: !*noNetwork,
	})

	if *jsonOutput {
		if err := report.WriteJSON(os.Stdout); err != nil {
			fmt.Fprintf(os.Stderr, "could not write JSON report: %v\n", err)
			os.Exit(2)
		}
	} else {
		report.WriteText(os.Stdout, *verbose)
	}
	os.Exit(report.ExitCode)
}
