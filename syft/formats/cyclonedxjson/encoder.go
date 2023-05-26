package cyclonedxjson

import (
	"io"

	"github.com/CycloneDX/cyclonedx-go"

	"github.com/nextlinux/gosbom/syft/formats/common/cyclonedxhelpers"
	"github.com/nextlinux/gosbom/syft/sbom"
)

func encoder(output io.Writer, s sbom.SBOM) error {
	bom := cyclonedxhelpers.ToFormatModel(s)
	enc := cyclonedx.NewBOMEncoder(output, cyclonedx.BOMFileFormatJSON)
	enc.SetPretty(true)
	enc.SetEscapeHTML(false)
	err := enc.Encode(bom)
	return err
}
