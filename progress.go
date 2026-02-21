package main

import (
	"fmt"

	"github.com/schollz/progressbar/v3"
)

// ProgressUpdater is a common interface for progress tracking.
type ProgressUpdater interface {
	Increment()
	Finish()
}

// realProgressBar wraps schollz/progressbar.
type realProgressBar struct {
	bar *progressbar.ProgressBar
}

func newProgressBar(total int, description string) ProgressUpdater {
	if silent {
		return &noopProgressBar{}
	}
	bar := progressbar.NewOptions(total,
		progressbar.OptionSetDescription(fmt.Sprintf("  %s", description)),
		progressbar.OptionSetWidth(30),
		progressbar.OptionShowCount(),
		progressbar.OptionClearOnFinish(),
		progressbar.OptionSetPredictTime(false),
	)
	return &realProgressBar{bar: bar}
}

func (p *realProgressBar) Increment() {
	p.bar.Add(1)
}

func (p *realProgressBar) Finish() {
	p.bar.Finish()
}

// noopProgressBar is used in silent/JSON mode.
type noopProgressBar struct{}

func (n *noopProgressBar) Increment() {}
func (n *noopProgressBar) Finish()    {}
