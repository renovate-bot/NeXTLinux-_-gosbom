package syftjson

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/Masterminds/semver"

	"github.com/nextlinux/gosbom/gosbom/formats/syftjson/model"
	"github.com/nextlinux/gosbom/gosbom/sbom"
	"github.com/nextlinux/gosbom/internal"
	"github.com/nextlinux/gosbom/internal/log"
)

func decoder(reader io.Reader) (*sbom.SBOM, error) {
	dec := json.NewDecoder(reader)

	var doc model.Document
	err := dec.Decode(&doc)
	if err != nil {
		return nil, fmt.Errorf("unable to decode syft-json: %w", err)
	}

	if err := checkSupportedSchema(doc.Schema.Version, internal.JSONSchemaVersion); err != nil {
		log.Warn(err)
	}

	return toSyftModel(doc)
}

func checkSupportedSchema(documentVerion string, parserVersion string) error {
	documentV, err := semver.NewVersion(documentVerion)
	if err != nil {
		return fmt.Errorf("error comparing document schema version with parser schema version: %w", err)
	}

	parserV, err := semver.NewVersion(parserVersion)
	if err != nil {
		return fmt.Errorf("error comparing document schema version with parser schema version: %w", err)
	}

	if documentV.GreaterThan(parserV) {
		return fmt.Errorf("document has schema version %s, but parser has older schema version (%s)", documentVerion, parserVersion)
	}

	return nil
}
