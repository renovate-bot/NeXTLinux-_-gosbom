package syft

import (
	"github.com/nextlinux/gosbom/gosbom/formats"
	"github.com/nextlinux/gosbom/gosbom/formats/cyclonedxjson"
	"github.com/nextlinux/gosbom/gosbom/formats/cyclonedxxml"
	"github.com/nextlinux/gosbom/gosbom/formats/github"
	"github.com/nextlinux/gosbom/gosbom/formats/spdxjson"
	"github.com/nextlinux/gosbom/gosbom/formats/spdxtagvalue"
	"github.com/nextlinux/gosbom/gosbom/formats/syftjson"
	"github.com/nextlinux/gosbom/gosbom/formats/table"
	"github.com/nextlinux/gosbom/gosbom/formats/template"
	"github.com/nextlinux/gosbom/gosbom/formats/text"
	"github.com/nextlinux/gosbom/gosbom/sbom"
)

// these have been exported for the benefit of API users
// TODO: deprecated: now that the formats package has been moved to syft/formats, will be removed in v1.0.0
const (
	JSONFormatID          = syftjson.ID
	TextFormatID          = text.ID
	TableFormatID         = table.ID
	CycloneDxXMLFormatID  = cyclonedxxml.ID
	CycloneDxJSONFormatID = cyclonedxjson.ID
	GitHubFormatID        = github.ID
	SPDXTagValueFormatID  = spdxtagvalue.ID
	SPDXJSONFormatID      = spdxjson.ID
	TemplateFormatID      = template.ID
)

// TODO: deprecated, moved to syft/formats/formats.go. will be removed in v1.0.0
func FormatIDs() (ids []sbom.FormatID) {
	return formats.AllIDs()
}

// TODO: deprecated, moved to syft/formats/formats.go. will be removed in v1.0.0
func FormatByID(id sbom.FormatID) sbom.Format {
	return formats.ByNameAndVersion(string(id), "")
}

// TODO: deprecated, moved to syft/formats/formats.go. will be removed in v1.0.0
func FormatByName(name string) sbom.Format {
	return formats.ByName(name)
}

// TODO: deprecated, moved to syft/formats/formats.go. will be removed in v1.0.0
func IdentifyFormat(by []byte) sbom.Format {
	return formats.Identify(by)
}
