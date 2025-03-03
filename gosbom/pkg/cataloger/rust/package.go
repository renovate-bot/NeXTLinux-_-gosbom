package rust

import (
	"github.com/anchore/packageurl-go"
	"github.com/microsoft/go-rustaudit"

	"github.com/nextlinux/gosbom/gosbom/file"
	"github.com/nextlinux/gosbom/gosbom/pkg"
)

// Pkg returns the standard `pkg.Package` representation of the package referenced within the Cargo.lock metadata.
func newPackageFromCargoMetadata(m pkg.CargoPackageMetadata, locations ...file.Location) pkg.Package {
	p := pkg.Package{
		Name:         m.Name,
		Version:      m.Version,
		Locations:    file.NewLocationSet(locations...),
		PURL:         packageURL(m.Name, m.Version),
		Language:     pkg.Rust,
		Type:         pkg.RustPkg,
		MetadataType: pkg.RustCargoPackageMetadataType,
		Metadata:     m,
	}

	p.SetID()

	return p
}

func newPackagesFromAudit(location file.Location, versionInfo rustaudit.VersionInfo) []pkg.Package {
	var pkgs []pkg.Package

	for _, dep := range versionInfo.Packages {
		dep := dep
		p := newPackageFromAudit(&dep, location.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation))
		if pkg.IsValid(&p) && dep.Kind == rustaudit.Runtime {
			pkgs = append(pkgs, p)
		}
	}

	return pkgs
}

func newPackageFromAudit(dep *rustaudit.Package, locations ...file.Location) pkg.Package {
	p := pkg.Package{
		Name:         dep.Name,
		Version:      dep.Version,
		PURL:         packageURL(dep.Name, dep.Version),
		Language:     pkg.Rust,
		Type:         pkg.RustPkg,
		Locations:    file.NewLocationSet(locations...),
		MetadataType: pkg.RustCargoPackageMetadataType,
		Metadata: pkg.CargoPackageMetadata{
			Name:    dep.Name,
			Version: dep.Version,
			Source:  dep.Source,
		},
	}

	p.SetID()

	return p
}

// packageURL returns the PURL for the specific rust package (see https://github.com/package-url/purl-spec)
func packageURL(name, version string) string {
	return packageurl.NewPackageURL(
		packageurl.TypeCargo,
		"",
		name,
		version,
		nil,
		"",
	).ToString()
}
