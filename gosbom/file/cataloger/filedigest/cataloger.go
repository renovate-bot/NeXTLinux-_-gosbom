package filedigest

import (
	"crypto"
	"errors"

	stereoscopeFile "github.com/anchore/stereoscope/pkg/file"
	"github.com/wagoodman/go-partybus"
	"github.com/wagoodman/go-progress"

	"github.com/nextlinux/gosbom/gosbom/event"
	"github.com/nextlinux/gosbom/gosbom/file"
	internal2 "github.com/nextlinux/gosbom/gosbom/file/cataloger/internal"
	"github.com/nextlinux/gosbom/internal"
	"github.com/nextlinux/gosbom/internal/bus"
	"github.com/nextlinux/gosbom/internal/log"
)

var ErrUndigestableFile = errors.New("undigestable file")

type Cataloger struct {
	hashes []crypto.Hash
}

func NewCataloger(hashes []crypto.Hash) *Cataloger {
	return &Cataloger{
		hashes: hashes,
	}
}

func (i *Cataloger) Catalog(resolver file.Resolver, coordinates ...file.Coordinates) (map[file.Coordinates][]file.Digest, error) {
	results := make(map[file.Coordinates][]file.Digest)
	var locations []file.Location

	if len(coordinates) == 0 {
		locations = internal2.AllRegularFiles(resolver)
	} else {
		for _, c := range coordinates {
			locations = append(locations, file.NewLocationFromCoordinates(c))
		}
	}

	stage, prog := digestsCatalogingProgress(int64(len(locations)))
	for _, location := range locations {
		stage.Current = location.RealPath
		result, err := i.catalogLocation(resolver, location)

		if errors.Is(err, ErrUndigestableFile) {
			continue
		}

		if internal.IsErrPathPermission(err) {
			log.Debugf("file digests cataloger skipping %q: %+v", location.RealPath, err)
			continue
		}

		if err != nil {
			return nil, err
		}
		prog.Increment()
		results[location.Coordinates] = result
	}
	log.Debugf("file digests cataloger processed %d files", prog.Current())
	prog.SetCompleted()
	return results, nil
}

func (i *Cataloger) catalogLocation(resolver file.Resolver, location file.Location) ([]file.Digest, error) {
	meta, err := resolver.FileMetadataByLocation(location)
	if err != nil {
		return nil, err
	}

	// we should only attempt to report digests for files that are regular files (don't attempt to resolve links)
	if meta.Type != stereoscopeFile.TypeRegular {
		return nil, ErrUndigestableFile
	}

	contentReader, err := resolver.FileContentsByLocation(location)
	if err != nil {
		return nil, err
	}
	defer internal.CloseAndLogError(contentReader, location.VirtualPath)

	digests, err := file.NewDigestsFromFile(contentReader, i.hashes)
	if err != nil {
		return nil, internal.ErrPath{Context: "digests-cataloger", Path: location.RealPath, Err: err}
	}

	return digests, nil
}

func digestsCatalogingProgress(locations int64) (*progress.Stage, *progress.Manual) {
	stage := &progress.Stage{}
	prog := progress.NewManual(locations)

	bus.Publish(partybus.Event{
		Type: event.FileDigestsCatalogerStarted,
		Value: struct {
			progress.Stager
			progress.Progressable
		}{
			Stager:       progress.Stager(stage),
			Progressable: prog,
		},
	})

	return stage, prog
}
