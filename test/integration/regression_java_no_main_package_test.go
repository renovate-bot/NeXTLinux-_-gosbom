package integration

import (
	"testing"

	"github.com/nextlinux/gosbom/gosbom/source"
)

func TestRegressionJavaNoMainPackage(t *testing.T) { // Regression: https://github.com/nextlinux/gosbom/issues/252
	catalogFixtureImage(t, "image-java-no-main-package", source.SquashedScope, nil)
}
