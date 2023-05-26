package syftjson

import (
	"github.com/nextlinux/gosbom/internal"
	"github.com/nextlinux/gosbom/syft/sbom"
)

const ID sbom.FormatID = "syft-json"

func Format() sbom.Format {
	return sbom.NewFormat(
		internal.JSONSchemaVersion,
		encoder,
		decoder,
		validator,
		ID, "json", "syft",
	)
}
