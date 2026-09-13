package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	var err error
	switch os.Args[1] {
	case "collect":
		err = runCollect(os.Args[2:])
	case "match":
		err = runMatch(os.Args[2:])
	case "-h", "-help", "--help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}

	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `usage: %s <subcommand> [flags]

subcommands:
  collect   sample running containers' procfs/Docker-API evidence
  match     match a collect observation against a Trivy scan and a case definition

Run "%s <subcommand> -h" for subcommand flags.
`, os.Args[0], os.Args[0])
}
