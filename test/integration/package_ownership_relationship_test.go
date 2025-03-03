package integration

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/nextlinux/gosbom/gosbom/formats/syftjson"
	syftjsonModel "github.com/nextlinux/gosbom/gosbom/formats/syftjson/model"
	"github.com/nextlinux/gosbom/gosbom/source"
)

func TestPackageOwnershipRelationships(t *testing.T) {

	// ensure that the json encoder is applying artifact ownership with an image that has expected ownership relationships
	tests := []struct {
		fixture string
	}{
		{
			fixture: "image-owning-package",
		},
	}

	for _, test := range tests {
		t.Run(test.fixture, func(t *testing.T) {
			sbom, _ := catalogFixtureImage(t, test.fixture, source.SquashedScope, nil)

			output := bytes.NewBufferString("")
			err := syftjson.Format().Encode(output, sbom)
			if err != nil {
				t.Fatalf("unable to present: %+v", err)
			}

			var doc syftjsonModel.Document
			decoder := json.NewDecoder(output)
			if err := decoder.Decode(&doc); err != nil {
				t.Fatalf("unable to decode json doc: %+v", err)
			}

			if len(doc.ArtifactRelationships) == 0 {
				t.Errorf("expected to find relationships between packages but found none")
			}

		})
	}

}
