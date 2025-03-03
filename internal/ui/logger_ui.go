package ui

import (
	"github.com/wagoodman/go-partybus"

	syftEvent "github.com/nextlinux/gosbom/gosbom/event"
	"github.com/nextlinux/gosbom/internal/log"
)

type loggerUI struct {
	unsubscribe func() error
}

// NewLoggerUI writes all events to the common application logger and writes the final report to the given writer.
func NewLoggerUI() UI {
	return &loggerUI{}
}

func (l *loggerUI) Setup(unsubscribe func() error) error {
	l.unsubscribe = unsubscribe
	return nil
}

func (l loggerUI) Handle(event partybus.Event) error {
	// ignore all events except for the final event
	if event.Type != syftEvent.Exit {
		return nil
	}

	if err := handleExit(event); err != nil {
		log.Warnf("unable to show catalog image finished event: %+v", err)
	}

	// this is the last expected event, stop listening to events
	return l.unsubscribe()
}

func (l loggerUI) Teardown(_ bool) error {
	return nil
}
