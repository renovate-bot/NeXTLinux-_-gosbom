package rust

import (
	"errors"

	rustaudit "github.com/microsoft/go-rustaudit"

	"github.com/nextlinux/gosbom/gosbom/artifact"
	"github.com/nextlinux/gosbom/gosbom/file"
	"github.com/nextlinux/gosbom/gosbom/pkg"
	"github.com/nextlinux/gosbom/gosbom/pkg/cataloger/generic"
	"github.com/nextlinux/gosbom/gosbom/pkg/cataloger/internal/unionreader"
	"github.com/nextlinux/gosbom/internal/log"
)

// Catalog identifies executables then attempts to read Rust dependency information from them
func parseAuditBinary(_ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	var pkgs []pkg.Package

	unionReader, err := unionreader.GetUnionReader(reader.ReadCloser)
	if err != nil {
		return nil, nil, err
	}

	for _, versionInfo := range parseAuditBinaryEntry(unionReader, reader.RealPath) {
		pkgs = append(pkgs, newPackagesFromAudit(reader.Location, versionInfo)...)
	}

	return pkgs, nil, nil
}

// scanFile scans file to try to report the Rust crate dependencies
func parseAuditBinaryEntry(reader unionreader.UnionReader, filename string) []rustaudit.VersionInfo {
	// NOTE: multiple readers are returned to cover universal binaries, which are files
	// with more than one binary
	readers, err := unionreader.GetReaders(reader)
	if err != nil {
		log.Warnf("rust cataloger: failed to open a binary: %v", err)
		return nil
	}

	var versionInfos []rustaudit.VersionInfo
	for _, r := range readers {
		versionInfo, err := rustaudit.GetDependencyInfo(r)

		if err != nil {
			if errors.Is(err, rustaudit.ErrNoRustDepInfo) {
				// since the cataloger can only select executables and not distinguish if they are a Rust-compiled
				// binary, we should not show warnings/logs in this case.
				return nil
			}
			// Use an Info level log here like golang/scan_bin.go
			log.Infof("rust cataloger: unable to read dependency information (file=%q): %v", filename, err)
			return nil
		}

		versionInfos = append(versionInfos, versionInfo)
	}

	return versionInfos
}
