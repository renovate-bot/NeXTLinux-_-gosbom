package integration

import (
	"testing"

	"github.com/nextlinux/gosbom/gosbom/pkg"
	"github.com/nextlinux/gosbom/gosbom/source"
)

func TestMarinerDistroless(t *testing.T) {
	sbom, _ := catalogFixtureImage(t, "image-mariner-distroless", source.SquashedScope, nil)

	expectedPkgs := 12
	actualPkgs := 0
	for range sbom.Artifacts.Packages.Enumerate(pkg.RpmPkg) {
		actualPkgs += 1
	}

	if actualPkgs != expectedPkgs {
		t.Errorf("unexpected number of RPM packages: %d != %d", expectedPkgs, actualPkgs)
	}
}
