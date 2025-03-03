package dotnet

import (
	"strings"

	"github.com/anchore/packageurl-go"

	"github.com/nextlinux/gosbom/gosbom/file"
	"github.com/nextlinux/gosbom/gosbom/pkg"
)

func newDotnetDepsPackage(nameVersion string, lib dotnetDepsLibrary, locations ...file.Location) *pkg.Package {
	if lib.Type != "package" {
		return nil
	}

	fields := strings.Split(nameVersion, "/")
	name := fields[0]
	version := fields[1]

	m := pkg.DotnetDepsMetadata{
		Name:     name,
		Version:  version,
		Path:     lib.Path,
		Sha512:   lib.Sha512,
		HashPath: lib.HashPath,
	}

	p := &pkg.Package{
		Name:         name,
		Version:      version,
		Locations:    file.NewLocationSet(locations...),
		PURL:         packageURL(m),
		Language:     pkg.Dotnet,
		Type:         pkg.DotnetPkg,
		MetadataType: pkg.DotnetDepsMetadataType,
		Metadata:     m,
	}

	p.SetID()

	return p
}

func packageURL(m pkg.DotnetDepsMetadata) string {
	var qualifiers packageurl.Qualifiers

	return packageurl.NewPackageURL(
		// This originally was packageurl.TypeDotnet, but this isn't a valid PURL type, according to:
		// https://github.com/package-url/purl-spec/blob/master/PURL-TYPES.rst
		// Some history:
		//   https://github.com/anchore/packageurl-go/pull/8 added the type to Anchore's fork
		//   due to this PR: https://github.com/nextlinux/gosbom/pull/951
		// There were questions about "dotnet" being the right purlType at the time, but it was
		// acknowledged that scanning a dotnet file does not necessarily mean the packages found
		// are nuget packages and so the alternate type was added. Since this is still an invalid
		// PURL type, however, we will use TypeNuget and revisit at such time there is a better
		// official PURL type available.
		packageurl.TypeNuget,
		"",
		m.Name,
		m.Version,
		qualifiers,
		"",
	).ToString()
}
