package poweruser

import (
	"context"
	"fmt"
	"os"

	"github.com/anchore/stereoscope"
	"github.com/gookit/color"
	"github.com/wagoodman/go-partybus"

	"github.com/nextlinux/gosbom/cmd/gosbom/cli/eventloop"
	"github.com/nextlinux/gosbom/cmd/gosbom/cli/options"
	"github.com/nextlinux/gosbom/cmd/gosbom/cli/packages"
	syft "github.com/nextlinux/gosbom/gosbom"
	"github.com/nextlinux/gosbom/gosbom/artifact"
	"github.com/nextlinux/gosbom/gosbom/event"
	"github.com/nextlinux/gosbom/gosbom/formats/syftjson"
	"github.com/nextlinux/gosbom/gosbom/sbom"
	"github.com/nextlinux/gosbom/gosbom/source"
	"github.com/nextlinux/gosbom/internal"
	"github.com/nextlinux/gosbom/internal/bus"
	"github.com/nextlinux/gosbom/internal/config"
	"github.com/nextlinux/gosbom/internal/log"
	"github.com/nextlinux/gosbom/internal/ui"
	"github.com/nextlinux/gosbom/internal/version"
)

func Run(_ context.Context, app *config.Application, args []string) error {
	f := syftjson.Format()
	writer, err := sbom.NewWriter(sbom.WriterOption{
		Format: f,
		Path:   app.File,
	})
	if err != nil {
		return err
	}

	defer func() {
		if err := writer.Close(); err != nil {
			log.Warnf("unable to write to report destination: %+v", err)
		}

		// inform user at end of run that command will be removed
		deprecated := color.Style{color.Red, color.OpBold}.Sprint("DEPRECATED: This command will be removed in v1.0.0")
		fmt.Fprintln(os.Stderr, deprecated)
	}()

	userInput := args[0]
	si, err := source.ParseInputWithName(userInput, app.Platform, app.Name, app.DefaultImagePullSource)
	if err != nil {
		return fmt.Errorf("could not generate source input for packages command: %w", err)
	}

	eventBus := partybus.NewBus()
	stereoscope.SetBus(eventBus)
	syft.SetBus(eventBus)
	subscription := eventBus.Subscribe()

	return eventloop.EventLoop(
		execWorker(app, *si, writer),
		eventloop.SetupSignals(),
		subscription,
		stereoscope.Cleanup,
		ui.Select(options.IsVerbose(app), app.Quiet)...,
	)
}

func execWorker(app *config.Application, si source.Input, writer sbom.Writer) <-chan error {
	errs := make(chan error)
	go func() {
		defer close(errs)

		app.Secrets.Cataloger.Enabled = true
		app.FileMetadata.Cataloger.Enabled = true
		app.FileContents.Cataloger.Enabled = true
		app.FileClassification.Cataloger.Enabled = true
		tasks, err := eventloop.Tasks(app)
		if err != nil {
			errs <- err
			return
		}

		src, cleanup, err := source.New(si, app.Registry.ToOptions(), app.Exclusions)
		if err != nil {
			errs <- err
			return
		}
		if cleanup != nil {
			defer cleanup()
		}

		s := sbom.SBOM{
			Source: src.Metadata,
			Descriptor: sbom.Descriptor{
				Name:          internal.ApplicationName,
				Version:       version.FromBuild().Version,
				Configuration: app,
			},
		}

		var relationships []<-chan artifact.Relationship
		for _, task := range tasks {
			c := make(chan artifact.Relationship)
			relationships = append(relationships, c)

			go eventloop.RunTask(task, &s.Artifacts, src, c, errs)
		}

		s.Relationships = append(s.Relationships, packages.MergeRelationships(relationships...)...)

		bus.Publish(partybus.Event{
			Type:  event.Exit,
			Value: func() error { return writer.Write(s) },
		})
	}()

	return errs
}
