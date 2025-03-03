package filedigest

import (
	"crypto"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	stereoscopeFile "github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/stereoscope/pkg/imagetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nextlinux/gosbom/gosbom/file"
	"github.com/nextlinux/gosbom/gosbom/source"
)

func testDigests(t testing.TB, root string, files []string, hashes ...crypto.Hash) map[file.Coordinates][]file.Digest {
	digests := make(map[file.Coordinates][]file.Digest)

	for _, f := range files {
		fh, err := os.Open(filepath.Join(root, f))
		if err != nil {
			t.Fatalf("could not open %q : %+v", f, err)
		}
		b, err := io.ReadAll(fh)
		if err != nil {
			t.Fatalf("could not read %q : %+v", f, err)
		}

		if len(b) == 0 {
			// we don't keep digests for empty files
			digests[file.NewLocation(f).Coordinates] = []file.Digest{}
			continue
		}

		for _, hash := range hashes {
			h := hash.New()
			h.Write(b)
			digests[file.NewLocation(f).Coordinates] = append(digests[file.NewLocation(f).Coordinates], file.Digest{
				Algorithm: file.CleanDigestAlgorithmName(hash.String()),
				Value:     fmt.Sprintf("%x", h.Sum(nil)),
			})
		}
	}

	return digests
}

func TestDigestsCataloger(t *testing.T) {

	tests := []struct {
		name     string
		digests  []crypto.Hash
		files    []string
		expected map[file.Coordinates][]file.Digest
	}{
		{
			name:     "md5",
			digests:  []crypto.Hash{crypto.MD5},
			files:    []string{"test-fixtures/last/empty/empty", "test-fixtures/last/path.txt"},
			expected: testDigests(t, "test-fixtures/last", []string{"empty/empty", "path.txt"}, crypto.MD5),
		},
		{
			name:     "md5-sha1-sha256",
			digests:  []crypto.Hash{crypto.MD5, crypto.SHA1, crypto.SHA256},
			files:    []string{"test-fixtures/last/empty/empty", "test-fixtures/last/path.txt"},
			expected: testDigests(t, "test-fixtures/last", []string{"empty/empty", "path.txt"}, crypto.MD5, crypto.SHA1, crypto.SHA256),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			c := NewCataloger(test.digests)

			src, err := source.NewFromDirectory("test-fixtures/last/")
			require.NoError(t, err)

			resolver, err := src.FileResolver(source.SquashedScope)
			require.NoError(t, err)

			actual, err := c.Catalog(resolver)
			require.NoError(t, err)

			assert.Equal(t, test.expected, actual, "mismatched digests")
		})
	}
}

func TestDigestsCataloger_MixFileTypes(t *testing.T) {
	testImage := "image-file-type-mix"

	img := imagetest.GetFixtureImage(t, "docker-archive", testImage)

	src, err := source.NewFromImage(img, "---")
	if err != nil {
		t.Fatalf("could not create source: %+v", err)
	}

	resolver, err := src.FileResolver(source.SquashedScope)
	if err != nil {
		t.Fatalf("could not create resolver: %+v", err)
	}

	tests := []struct {
		path     string
		expected string
	}{
		{
			path:     "/file-1.txt",
			expected: "888c139e550867814eb7c33b84d76e4d",
		},
		// this is difficult to reproduce in a cross-platform way
		//{
		//	path: "/hardlink-1",
		//},
		{
			path: "/symlink-1",
		},
		{
			path: "/char-device-1",
		},
		{
			path: "/block-device-1",
		},
		{
			path: "/fifo-1",
		},
		{
			path: "/bin",
		},
	}

	for _, test := range tests {
		t.Run(test.path, func(t *testing.T) {
			c := NewCataloger([]crypto.Hash{crypto.MD5})

			actual, err := c.Catalog(resolver)
			if err != nil {
				t.Fatalf("could not catalog: %+v", err)
			}

			_, ref, err := img.SquashedTree().File(stereoscopeFile.Path(test.path))
			if err != nil {
				t.Fatalf("unable to get file=%q : %+v", test.path, err)
			}
			l := file.NewLocationFromImage(test.path, *ref.Reference, img)

			if len(actual[l.Coordinates]) == 0 {
				if test.expected != "" {
					t.Fatalf("no digest found, but expected one")
				}

			} else {
				assert.Equal(t, actual[l.Coordinates][0].Value, test.expected, "mismatched digests")
			}
		})
	}
}
