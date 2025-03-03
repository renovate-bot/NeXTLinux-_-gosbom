package text

import (
	"github.com/nextlinux/gosbom/gosbom/sbom"
)

const ID sbom.FormatID = "syft-text"

func Format() sbom.Format {
	return sbom.NewFormat(
		sbom.AnyVersion,
		encoder,
		nil,
		nil,
		ID, "text",
	)
}
