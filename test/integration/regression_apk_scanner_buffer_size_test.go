package integration

import (
	"testing"

	"github.com/nextlinux/gosbom/gosbom/pkg"
	"github.com/nextlinux/gosbom/gosbom/source"
)

func TestRegression212ApkBufferSize(t *testing.T) {
	// This is a regression test for issue #212 (https://github.com/nextlinux/gosbom/issues/212) in which the apk db could
	// not be processed due to a scanner buffer that was too small
	sbom, _ := catalogFixtureImage(t, "image-large-apk-data", source.SquashedScope, nil)

	expectedPkgs := 58
	actualPkgs := 0
	for range sbom.Artifacts.Packages.Enumerate(pkg.ApkPkg) {
		actualPkgs += 1
	}

	if actualPkgs != expectedPkgs {
		t.Errorf("unexpected number of APK packages: %d != %d", expectedPkgs, actualPkgs)
	}
}
