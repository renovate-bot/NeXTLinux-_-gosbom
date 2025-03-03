package filemetadata

import (
	"os"
	"testing"

	stereoscopeFile "github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/stereoscope/pkg/imagetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nextlinux/gosbom/gosbom/file"
	"github.com/nextlinux/gosbom/gosbom/source"
)

func TestFileMetadataCataloger(t *testing.T) {
	testImage := "image-file-type-mix"

	img := imagetest.GetFixtureImage(t, "docker-archive", testImage)

	c := NewCataloger()

	src, err := source.NewFromImage(img, "---")
	if err != nil {
		t.Fatalf("could not create source: %+v", err)
	}

	resolver, err := src.FileResolver(source.SquashedScope)
	if err != nil {
		t.Fatalf("could not create resolver: %+v", err)
	}

	actual, err := c.Catalog(resolver)
	if err != nil {
		t.Fatalf("could not catalog: %+v", err)
	}

	tests := []struct {
		path     string
		exists   bool
		expected file.Metadata
		err      bool
	}{
		// note: it is difficult to add a hardlink-based test in a cross-platform way and is already covered well in stereoscope
		{
			path:   "/file-1.txt",
			exists: true,
			expected: file.Metadata{
				FileInfo: stereoscopeFile.ManualInfo{
					NameValue: "file-1.txt",
					ModeValue: 0644,
					SizeValue: 7,
				},
				Path:     "/file-1.txt",
				Type:     stereoscopeFile.TypeRegular,
				UserID:   1,
				GroupID:  2,
				MIMEType: "text/plain",
			},
		},
		{
			path:   "/symlink-1",
			exists: true,
			expected: file.Metadata{
				Path: "/symlink-1",
				FileInfo: stereoscopeFile.ManualInfo{
					NameValue: "symlink-1",
					ModeValue: 0777 | os.ModeSymlink,
				},
				Type:            stereoscopeFile.TypeSymLink,
				LinkDestination: "file-1.txt",
				UserID:          0,
				GroupID:         0,
				MIMEType:        "",
			},
		},
		{
			path:   "/char-device-1",
			exists: true,
			expected: file.Metadata{
				Path: "/char-device-1",
				FileInfo: stereoscopeFile.ManualInfo{
					NameValue: "char-device-1",
					ModeValue: 0644 | os.ModeDevice | os.ModeCharDevice,
				},
				Type:     stereoscopeFile.TypeCharacterDevice,
				UserID:   0,
				GroupID:  0,
				MIMEType: "",
			},
		},
		{
			path:   "/block-device-1",
			exists: true,
			expected: file.Metadata{
				Path: "/block-device-1",
				FileInfo: stereoscopeFile.ManualInfo{
					NameValue: "block-device-1",
					ModeValue: 0644 | os.ModeDevice,
				},
				Type:     stereoscopeFile.TypeBlockDevice,
				UserID:   0,
				GroupID:  0,
				MIMEType: "",
			},
		},
		{
			path:   "/fifo-1",
			exists: true,
			expected: file.Metadata{
				Path: "/fifo-1",
				FileInfo: stereoscopeFile.ManualInfo{
					NameValue: "fifo-1",
					ModeValue: 0644 | os.ModeNamedPipe,
				},
				Type:     stereoscopeFile.TypeFIFO,
				UserID:   0,
				GroupID:  0,
				MIMEType: "",
			},
		},
		{
			path:   "/bin",
			exists: true,
			expected: file.Metadata{
				Path: "/bin",
				FileInfo: stereoscopeFile.ManualInfo{
					NameValue: "bin",
					ModeValue: 0755 | os.ModeDir,
				},
				Type:     stereoscopeFile.TypeDirectory,
				UserID:   0,
				GroupID:  0,
				MIMEType: "",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.path, func(t *testing.T) {
			_, ref, err := img.SquashedTree().File(stereoscopeFile.Path(test.path))
			require.NoError(t, err)

			l := file.NewLocationFromImage(test.path, *ref.Reference, img)

			if _, ok := actual[l.Coordinates]; ok {
				// we're not interested in keeping the test fixtures up to date with the latest file modification times
				// thus ModTime is not under test
				fi := test.expected.FileInfo.(stereoscopeFile.ManualInfo)
				fi.ModTimeValue = actual[l.Coordinates].ModTime()
				test.expected.FileInfo = fi
			}

			assert.True(t, test.expected.Equal(actual[l.Coordinates]))
		})
	}

}
