package file

import (
	"fmt"

	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/hashicorp/go-multierror"
)

// Location represents a path relative to a particular filesystem resolved to a specific file.Reference. This struct is used as a key
// in content fetching to uniquely identify a file relative to a request (the VirtualPath).
type Location struct {
	LocationData     `cyclonedx:""`
	LocationMetadata `cyclonedx:""`
}

type LocationData struct {
	Coordinates `cyclonedx:""` // Empty string here means there is no intermediate property name, e.g. syft:locations:0:path without "coordinates"
	// note: it is IMPORTANT to ignore anything but the coordinates for a Location when considering the ID (hash value)
	// since the coordinates are the minimally correct ID for a location (symlinks should not come into play)
	VirtualPath string         `hash:"ignore" json:"-"` // The path to the file which may or may not have hardlinks / symlinks
	ref         file.Reference `hash:"ignore"`          // The file reference relative to the stereoscope.FileCatalog that has more information about this location.
}

func (l LocationData) Reference() file.Reference {
	return l.ref
}

type LocationMetadata struct {
	Annotations map[string]string `json:"annotations,omitempty"` // Arbitrary key-value pairs that can be used to annotate a location
}

func (m *LocationMetadata) merge(other LocationMetadata) error {
	var errs error
	for k, v := range other.Annotations {
		if otherV, ok := m.Annotations[k]; ok {
			if v != otherV {
				err := fmt.Errorf("unable to merge location metadata: conflicting values for key=%q: %q != %q", k, v, otherV)
				errs = multierror.Append(errs, err)
				continue
			}
		}
		m.Annotations[k] = v
	}
	return errs
}

func (l Location) WithAnnotation(key, value string) Location {
	if l.LocationMetadata.Annotations == nil {
		l.LocationMetadata.Annotations = map[string]string{}
	}
	l.LocationMetadata.Annotations[key] = value
	return l
}

func (l Location) WithoutAnnotations() Location {
	l.LocationMetadata.Annotations = map[string]string{}

	return l
}

// NewLocation creates a new Location representing a path without denoting a filesystem or FileCatalog reference.
func NewLocation(realPath string) Location {
	return Location{
		LocationData: LocationData{
			Coordinates: Coordinates{
				RealPath: realPath,
			},
		},
		LocationMetadata: LocationMetadata{
			Annotations: map[string]string{},
		},
	}
}

// NewVirtualLocation creates a new location for a path accessed by a virtual path (a path with a symlink or hardlink somewhere in the path)
func NewVirtualLocation(realPath, virtualPath string) Location {
	return Location{
		LocationData: LocationData{
			Coordinates: Coordinates{
				RealPath: realPath,
			},
			VirtualPath: virtualPath,
		},
		LocationMetadata: LocationMetadata{
			Annotations: map[string]string{},
		}}
}

// NewLocationFromCoordinates creates a new location for the given Coordinates.
func NewLocationFromCoordinates(coordinates Coordinates) Location {
	return Location{
		LocationData: LocationData{
			Coordinates: coordinates,
		},
		LocationMetadata: LocationMetadata{
			Annotations: map[string]string{},
		}}
}

// NewVirtualLocationFromCoordinates creates a new location for the given Coordinates via a virtual path.
func NewVirtualLocationFromCoordinates(coordinates Coordinates, virtualPath string) Location {
	return Location{
		LocationData: LocationData{
			Coordinates: coordinates,
			VirtualPath: virtualPath,
		},
		LocationMetadata: LocationMetadata{
			Annotations: map[string]string{},
		}}
}

// NewLocationFromImage creates a new Location representing the given path (extracted from the Reference) relative to the given image.
func NewLocationFromImage(virtualPath string, ref file.Reference, img *image.Image) Location {
	layer := img.FileCatalog.Layer(ref)
	return Location{
		LocationData: LocationData{
			Coordinates: Coordinates{
				RealPath:     string(ref.RealPath),
				FileSystemID: layer.Metadata.Digest,
			},
			VirtualPath: virtualPath,
			ref:         ref,
		},
		LocationMetadata: LocationMetadata{
			Annotations: map[string]string{},
		},
	}
}

// NewLocationFromDirectory creates a new Location representing the given path (extracted from the Reference) relative to the given directory.
func NewLocationFromDirectory(responsePath string, ref file.Reference) Location {
	return Location{
		LocationData: LocationData{
			Coordinates: Coordinates{
				RealPath: responsePath,
			},
			ref: ref,
		},
		LocationMetadata: LocationMetadata{
			Annotations: map[string]string{},
		},
	}
}

// NewVirtualLocationFromDirectory creates a new Location representing the given path (extracted from the Reference) relative to the given directory with a separate virtual access path.
func NewVirtualLocationFromDirectory(responsePath, virtualResponsePath string, ref file.Reference) Location {
	if responsePath == virtualResponsePath {
		return NewLocationFromDirectory(responsePath, ref)
	}
	return Location{
		LocationData: LocationData{
			Coordinates: Coordinates{
				RealPath: responsePath,
			},
			VirtualPath: virtualResponsePath,
			ref:         ref,
		},
		LocationMetadata: LocationMetadata{
			Annotations: map[string]string{},
		},
	}
}

func (l Location) AccessPath() string {
	if l.VirtualPath != "" {
		return l.VirtualPath
	}
	return l.RealPath
}

func (l Location) String() string {
	str := ""
	if l.ref.ID() != 0 {
		str += fmt.Sprintf("id=%d ", l.ref.ID())
	}

	str += fmt.Sprintf("RealPath=%q", l.RealPath)

	if l.VirtualPath != "" {
		str += fmt.Sprintf(" VirtualPath=%q", l.VirtualPath)
	}

	if l.FileSystemID != "" {
		str += fmt.Sprintf(" Layer=%q", l.FileSystemID)
	}
	return fmt.Sprintf("Location<%s>", str)
}

func (l Location) Equals(other Location) bool {
	return l.RealPath == other.RealPath &&
		l.VirtualPath == other.VirtualPath &&
		l.FileSystemID == other.FileSystemID
}
