package syftjson

import (
	"github.com/nextlinux/gosbom/gosbom/sbom"
	"github.com/nextlinux/gosbom/internal"
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
