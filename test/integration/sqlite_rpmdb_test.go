package integration

import (
	"testing"

	_ "modernc.org/sqlite"

	"github.com/nextlinux/gosbom/gosbom/pkg"
	"github.com/nextlinux/gosbom/gosbom/source"
)

func TestSqliteRpm(t *testing.T) {
	// This is a regression test for issue #469 (https://github.com/nextlinux/gosbom/issues/469). Recent RPM
	// based distribution store package data in an sqlite database
	sbom, _ := catalogFixtureImage(t, "image-sqlite-rpmdb", source.SquashedScope, nil)

	expectedPkgs := 139
	actualPkgs := 0
	for range sbom.Artifacts.Packages.Enumerate(pkg.RpmPkg) {
		actualPkgs += 1
	}

	if actualPkgs != expectedPkgs {
		t.Errorf("unexpected number of RPM packages: %d != %d", expectedPkgs, actualPkgs)
	}
}
