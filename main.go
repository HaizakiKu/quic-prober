package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/HaizakiKu/quic-prober/compare"
	"github.com/HaizakiKu/quic-prober/probe"
	"github.com/HaizakiKu/quic-prober/report"
	"github.com/HaizakiKu/quic-prober/ui"
)

type config struct {
	Target        string
	Reference     string
	ReferenceMode string
	Probes        string
	RandomSizes   string
	Timeout       int
	ProbeInterval int
	Verbose       bool
	JSON          bool
}

func main() {
	cfg := parseFlags()

	if cfg.Target == "" {
		fmt.Fprintln(os.Stderr, "error: --target is required")
		flag.Usage()
		os.Exit(2)
	}

	randomSizes := parseRandomSizes(cfg.RandomSizes)
	probes := selectProbes(cfg.Probes, randomSizes)
	references := splitTrim(cfg.Reference)
	refMode := compare.ReferenceMode(cfg.ReferenceMode)
	timeout := time.Duration(cfg.Timeout) * time.Second
	probeInterval := time.Duration(cfg.ProbeInterval) * time.Millisecond

	prog := ui.New(os.Stderr, !cfg.JSON && !cfg.Verbose && ui.IsTerminal(os.Stderr))

	prog.Update(ui.State{Action: "checking connectivity to " + cfg.Target + "…"})
	if err := probe.CheckConnectivity(cfg.Target, timeout); err != nil {
		prog.Clear()
		fmt.Fprintf(os.Stderr, "error: %s\n", err)
		os.Exit(2)
	}

	var comparisons []compare.Comparison

	for i, p := range probes {
		prog.Update(ui.State{
			ProbeName:   p.Name(),
			ProbeIndex:  i + 1,
			TotalProbes: len(probes),
			Action:      "probing target",
		})
		targetResult := probe.RunWithTimeout(p, cfg.Target, timeout)

		var refResults []probe.Result
		for j, ref := range references {
			time.Sleep(probeInterval)
			prog.Update(ui.State{
				ProbeName:   p.Name(),
				ProbeIndex:  i + 1,
				TotalProbes: len(probes),
				Action:      fmt.Sprintf("probing %s (ref %d/%d)", ref, j+1, len(references)),
			})
			r := probe.RunWithTimeout(p, ref, timeout)
			if cfg.Verbose {
				report.PrintVerboseResult(r)
			}
			refResults = append(refResults, r)
		}

		comparisons = append(comparisons, compare.Compare(targetResult, refResults, refMode))
		time.Sleep(probeInterval)
	}

	prog.Clear()

	if cfg.JSON {
		report.PrintJSON(comparisons)
	} else {
		report.PrintHuman(comparisons)
	}

	os.Exit(report.ExitCode(comparisons))
}

func parseFlags() config {
	cfg := config{}
	flag.StringVar(&cfg.Target, "target", "", "Target server (required). host:port")
	flag.StringVar(&cfg.Reference, "reference", "cloudflare.com:443", "Comma-separated reference servers")
	flag.StringVar(&cfg.ReferenceMode, "reference-mode", "any", "Reference merge mode: any, majority, all")
	flag.StringVar(&cfg.Probes, "probes", "all", "Comma-separated probe list: http3,tls,replay,null,random,malformed")
	flag.StringVar(&cfg.RandomSizes, "random-sizes", "1,8,16,32,64,128,256,512,1024,1400,1500", "Byte sizes for random probe")
	flag.IntVar(&cfg.Timeout, "timeout", 10, "Per-probe timeout in seconds")
	flag.IntVar(&cfg.ProbeInterval, "probe-interval", 2000, "Milliseconds between probes")
	flag.BoolVar(&cfg.Verbose, "verbose", false, "Show per-reference raw results")
	flag.BoolVar(&cfg.JSON, "json", false, "Output results as JSON")
	flag.Parse()
	return cfg
}

func parseRandomSizes(s string) []int {
	parts := splitTrim(s)
	sizes := make([]int, 0, len(parts))
	for _, p := range parts {
		n, err := strconv.Atoi(p)
		if err == nil && n > 0 {
			sizes = append(sizes, n)
		}
	}
	if len(sizes) == 0 {
		return probe.DefaultRandomSizes
	}
	return sizes
}

func selectProbes(names string, randomSizes []int) []probe.Probe {
	all := []probe.Probe{
		&probe.HTTP3Probe{},
		&probe.TLSProbe{},
		&probe.ReplayProbe{},
		&probe.NullProbe{},
		&probe.RandomProbe{Sizes: randomSizes},
		&probe.MalformedProbe{},
	}

	if strings.TrimSpace(names) == "all" {
		return all
	}

	wanted := make(map[string]bool)
	for _, n := range splitTrim(names) {
		wanted[n] = true
	}

	var selected []probe.Probe
	for _, p := range all {
		if wanted[p.Name()] {
			selected = append(selected, p)
		}
	}
	return selected
}

func splitTrim(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
