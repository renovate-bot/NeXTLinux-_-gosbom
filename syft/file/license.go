package file

import (
	"github.com/nextlinux/gosbom/internal/log"
	"github.com/nextlinux/gosbom/syft/license"
)

type License struct {
	Value           string
	SPDXExpression  string
	Type            license.Type
	LicenseEvidence *LicenseEvidence // evidence from license classifier
}

type LicenseEvidence struct {
	Confidence int
	Offset     int
	Extent     int
}

func NewLicense(value string) License {
	spdxExpression, err := license.ParseExpression(value)
	if err != nil {
		log.Trace("unable to parse license expression: %s, %w", value, err)
	}

	return License{
		Value:          value,
		SPDXExpression: spdxExpression,
		Type:           license.Concluded,
	}
}
