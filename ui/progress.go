package ui

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	numLines = 3
	barWidth = 20
)

var spinnerFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

// State describes progress at one moment in the probe loop
type State struct {
	ProbeName   string
	ProbeIndex  int
	TotalProbes int
	Action      string
}

type Progress struct {
	w       io.Writer
	enabled bool

	mu    sync.Mutex
	state State
	drawn bool
	frame int

	stopCh chan struct{}
	doneCh chan struct{}
}

func IsTerminal(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

func New(w io.Writer, enabled bool) *Progress {
	p := &Progress{
		w:       w,
		enabled: enabled,
		stopCh:  make(chan struct{}),
		doneCh:  make(chan struct{}),
	}
	if enabled {
		go p.loop()
	}
	return p
}

func (p *Progress) loop() {
	defer close(p.doneCh)
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			p.mu.Lock()
			p.redraw()
			p.mu.Unlock()
		case <-p.stopCh:
			return
		}
	}
}

func (p *Progress) Update(s State) {
	if !p.enabled {
		return
	}
	p.mu.Lock()
	p.state = s
	p.mu.Unlock()
}

func (p *Progress) Clear() {
	if !p.enabled {
		return
	}
	close(p.stopCh)
	<-p.doneCh

	p.mu.Lock()
	defer p.mu.Unlock()

	if !p.drawn {
		return
	}

	var buf bytes.Buffer
	fmt.Fprintf(&buf, "\x1b[%dA\r", numLines)
	for i := 0; i < numLines; i++ {
		fmt.Fprintf(&buf, "\x1b[2K")
		if i < numLines-1 {
			fmt.Fprintf(&buf, "\n")
		}
	}
	fmt.Fprintf(&buf, "\x1b[%dA\r", numLines-1)
	p.w.Write(buf.Bytes()) //nolint:errcheck
	p.drawn = false
}

func (p *Progress) redraw() {
	s := p.state

	spinner := spinnerFrames[p.frame%len(spinnerFrames)]
	p.frame++

	var buf bytes.Buffer

	if p.drawn {
		fmt.Fprintf(&buf, "\x1b[%dA", numLines)
	}

	var line1, line2 string
	if s.TotalProbes == 0 {
		line1 = fmt.Sprintf(" %s %s", spinner, truncate(s.Action, 72))
		line2 = ""
	} else {
		bar := buildBar(s.ProbeIndex-1, s.TotalProbes, barWidth)
		line1 = fmt.Sprintf(" %s [%d/%d] %s  %s", spinner, s.ProbeIndex, s.TotalProbes, bar, s.ProbeName)
		line2 = fmt.Sprintf("    → %s", truncate(s.Action, 58))
	}

	fmt.Fprintf(&buf, "\r\x1b[K%s\n", line1)
	fmt.Fprintf(&buf, "\r\x1b[K%s\n", line2)
	fmt.Fprintf(&buf, "\r\x1b[K\n") // blank line

	p.w.Write(buf.Bytes())
	p.drawn = true
}

func buildBar(done, total, width int) string {
	if total == 0 {
		return strings.Repeat("░", width)
	}
	filled := done * width / total
	if filled > width {
		filled = width
	}
	return strings.Repeat("█", filled) + strings.Repeat("░", width-filled)
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-1] + "…"
}
