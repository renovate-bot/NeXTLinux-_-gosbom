package internal

import (
	"testing"

	"github.com/anchore/stereoscope/pkg/imagetest"
	"github.com/google/go-cmp/cmp"
	"github.com/scylladb/go-set/strset"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nextlinux/gosbom/gosbom/file"
	"github.com/nextlinux/gosbom/gosbom/source"
)

func Test_allRegularFiles(t *testing.T) {
	tests := []struct {
		name             string
		setup            func() file.Resolver
		wantRealPaths    *strset.Set
		wantVirtualPaths *strset.Set
	}{
		{
			name: "image",
			setup: func() file.Resolver {
				testImage := "image-file-type-mix"

				img := imagetest.GetFixtureImage(t, "docker-archive", testImage)

				s, err := source.NewFromImage(img, "---")
				require.NoError(t, err)

				r, err := s.FileResolver(source.SquashedScope)
				require.NoError(t, err)

				return r
			},
			wantRealPaths:    strset.New("/file-1.txt"),
			wantVirtualPaths: strset.New("/file-1.txt", "/symlink-1", "/hardlink-1"),
		},
		{
			name: "directory",
			setup: func() file.Resolver {
				s, err := source.NewFromDirectory("test-fixtures/symlinked-root/nested/link-root")
				require.NoError(t, err)
				r, err := s.FileResolver(source.SquashedScope)
				require.NoError(t, err)
				return r
			},
			wantRealPaths:    strset.New("file1.txt", "nested/file2.txt"),
			wantVirtualPaths: strset.New("nested/linked-file1.txt"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resolver := tt.setup()
			locations := AllRegularFiles(resolver)
			realLocations := strset.New()
			virtualLocations := strset.New()
			for _, l := range locations {
				realLocations.Add(l.RealPath)
				if l.VirtualPath != "" {
					virtualLocations.Add(l.VirtualPath)
				}
			}

			// this is difficult to reproduce in a cross-platform way
			realLocations.Remove("/hardlink-1")
			virtualLocations.Remove("/hardlink-1")
			tt.wantRealPaths.Remove("/hardlink-1")
			tt.wantVirtualPaths.Remove("/hardlink-1")

			assert.ElementsMatch(t, tt.wantRealPaths.List(), realLocations.List(), "real paths differ: "+cmp.Diff(tt.wantRealPaths.List(), realLocations.List()))
			assert.ElementsMatch(t, tt.wantVirtualPaths.List(), virtualLocations.List(), "virtual paths differ: "+cmp.Diff(tt.wantVirtualPaths.List(), virtualLocations.List()))
		})
	}
}
