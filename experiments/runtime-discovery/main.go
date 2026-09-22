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
	case "supervise":
		err = runSupervise(os.Args[2:])
	case "cgroup-stat":
		err = runCgroupStat(os.Args[2:])
	case "cgroup-remove":
		err = runCgroupRemove(os.Args[2:])
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
  collect      sample running containers' procfs/Docker-API evidence
  match        match a collect observation against a Trivy scan and a case definition
  supervise    run one command inside a fresh cgroup v2 directory, verifying its actual
               exe/uid/CapEff and recording its own load and exit as JSON
  cgroup-stat  print one cgroup v2 directory's cpu.stat/memory.peak/cgroup.events as JSON
  cgroup-remove
               remove one cgroup v2 directory once it holds no task, reporting the attempt
               as JSON (the caller-side half of "supervise -keep-cgroup")

Run "%s <subcommand> -h" for subcommand flags.
`, os.Args[0], os.Args[0])
}
