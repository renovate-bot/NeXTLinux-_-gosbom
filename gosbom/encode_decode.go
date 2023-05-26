package syft

import (
	"io"

	"github.com/nextlinux/gosbom/gosbom/formats"
	"github.com/nextlinux/gosbom/gosbom/sbom"
)

// TODO: deprecated, moved to gosbom/formats/formats.go. will be removed in v1.0.0
func Encode(s sbom.SBOM, f sbom.Format) ([]byte, error) {
	return formats.Encode(s, f)
}

// TODO: deprecated, moved to gosbom/formats/formats.go. will be removed in v1.0.0
func Decode(reader io.Reader) (*sbom.SBOM, sbom.Format, error) {
	return formats.Decode(reader)
}
