/*
Package cataloger provides the ability to process files from a container image or file system and discover packages
(gems, wheels, jars, rpms, debs, etc). Specifically, this package contains both a catalog function to utilize all
catalogers defined in child packages as well as the interface definition to implement a cataloger.
*/
package cataloger

import (
	"strings"

	"github.com/nextlinux/gosbom/internal/log"
	"github.com/nextlinux/gosbom/syft/pkg"
	"github.com/nextlinux/gosbom/syft/pkg/cataloger/alpm"
	"github.com/nextlinux/gosbom/syft/pkg/cataloger/apkdb"
	"github.com/nextlinux/gosbom/syft/pkg/cataloger/binary"
	"github.com/nextlinux/gosbom/syft/pkg/cataloger/cpp"
	"github.com/nextlinux/gosbom/syft/pkg/cataloger/dart"
	"github.com/nextlinux/gosbom/syft/pkg/cataloger/deb"
	"github.com/nextlinux/gosbom/syft/pkg/cataloger/dotnet"
	"github.com/nextlinux/gosbom/syft/pkg/cataloger/elixir"
	"github.com/nextlinux/gosbom/syft/pkg/cataloger/erlang"
	"github.com/nextlinux/gosbom/syft/pkg/cataloger/golang"
	"github.com/nextlinux/gosbom/syft/pkg/cataloger/haskell"
	"github.com/nextlinux/gosbom/syft/pkg/cataloger/java"
	"github.com/nextlinux/gosbom/syft/pkg/cataloger/javascript"
	"github.com/nextlinux/gosbom/syft/pkg/cataloger/kernel"
	"github.com/nextlinux/gosbom/syft/pkg/cataloger/nix"
	"github.com/nextlinux/gosbom/syft/pkg/cataloger/php"
	"github.com/nextlinux/gosbom/syft/pkg/cataloger/portage"
	"github.com/nextlinux/gosbom/syft/pkg/cataloger/python"
	"github.com/nextlinux/gosbom/syft/pkg/cataloger/r"
	"github.com/nextlinux/gosbom/syft/pkg/cataloger/rpm"
	"github.com/nextlinux/gosbom/syft/pkg/cataloger/ruby"
	"github.com/nextlinux/gosbom/syft/pkg/cataloger/rust"
	"github.com/nextlinux/gosbom/syft/pkg/cataloger/sbom"
	"github.com/nextlinux/gosbom/syft/pkg/cataloger/swift"
)

const AllCatalogersPattern = "all"

// ImageCatalogers returns a slice of locally implemented catalogers that are fit for detecting installations of packages.
func ImageCatalogers(cfg Config) []pkg.Cataloger {
	return filterCatalogers([]pkg.Cataloger{
		alpm.NewAlpmdbCataloger(),
		apkdb.NewApkdbCataloger(),
		binary.NewCataloger(),
		deb.NewDpkgdbCataloger(),
		dotnet.NewDotnetDepsCataloger(),
		golang.NewGoModuleBinaryCataloger(cfg.Go()),
		java.NewJavaCataloger(cfg.Java()),
		java.NewNativeImageCataloger(),
		javascript.NewPackageCataloger(),
		nix.NewStoreCataloger(),
		php.NewComposerInstalledCataloger(),
		portage.NewPortageCataloger(),
		python.NewPythonPackageCataloger(),
		r.NewPackageCataloger(),
		rpm.NewRpmDBCataloger(),
		ruby.NewGemSpecCataloger(),
		sbom.NewSBOMCataloger(),
	}, cfg.Catalogers)
}

// DirectoryCatalogers returns a slice of locally implemented catalogers that are fit for detecting packages from index files (and select installations)
func DirectoryCatalogers(cfg Config) []pkg.Cataloger {
	return filterCatalogers([]pkg.Cataloger{
		alpm.NewAlpmdbCataloger(),
		apkdb.NewApkdbCataloger(),
		binary.NewCataloger(),
		cpp.NewConanCataloger(),
		dart.NewPubspecLockCataloger(),
		deb.NewDpkgdbCataloger(),
		dotnet.NewDotnetDepsCataloger(),
		elixir.NewMixLockCataloger(),
		erlang.NewRebarLockCataloger(),
		golang.NewGoModFileCataloger(cfg.Go()),
		golang.NewGoModuleBinaryCataloger(cfg.Go()),
		haskell.NewHackageCataloger(),
		java.NewJavaCataloger(cfg.Java()),
		java.NewJavaGradleLockfileCataloger(),
		java.NewJavaPomCataloger(),
		java.NewNativeImageCataloger(),
		javascript.NewLockCataloger(),
		nix.NewStoreCataloger(),
		php.NewComposerLockCataloger(),
		portage.NewPortageCataloger(),
		python.NewPythonIndexCataloger(),
		python.NewPythonPackageCataloger(),
		rpm.NewFileCataloger(),
		rpm.NewRpmDBCataloger(),
		ruby.NewGemFileLockCataloger(),
		rust.NewCargoLockCataloger(),
		sbom.NewSBOMCataloger(),
		swift.NewCocoapodsCataloger(),
	}, cfg.Catalogers)
}

// AllCatalogers returns all implemented catalogers
func AllCatalogers(cfg Config) []pkg.Cataloger {
	return filterCatalogers([]pkg.Cataloger{
		alpm.NewAlpmdbCataloger(),
		apkdb.NewApkdbCataloger(),
		binary.NewCataloger(),
		cpp.NewConanCataloger(),
		dart.NewPubspecLockCataloger(),
		deb.NewDpkgdbCataloger(),
		dotnet.NewDotnetDepsCataloger(),
		elixir.NewMixLockCataloger(),
		erlang.NewRebarLockCataloger(),
		golang.NewGoModFileCataloger(cfg.Go()),
		golang.NewGoModuleBinaryCataloger(cfg.Go()),
		haskell.NewHackageCataloger(),
		java.NewJavaCataloger(cfg.Java()),
		java.NewJavaGradleLockfileCataloger(),
		java.NewJavaPomCataloger(),
		java.NewNativeImageCataloger(),
		javascript.NewLockCataloger(),
		javascript.NewPackageCataloger(),
		kernel.NewLinuxKernelCataloger(cfg.Kernel()),
		nix.NewStoreCataloger(),
		php.NewComposerInstalledCataloger(),
		php.NewComposerLockCataloger(),
		portage.NewPortageCataloger(),
		python.NewPythonIndexCataloger(),
		python.NewPythonPackageCataloger(),
		r.NewPackageCataloger(),
		rpm.NewFileCataloger(),
		rpm.NewRpmDBCataloger(),
		ruby.NewGemFileLockCataloger(),
		ruby.NewGemSpecCataloger(),
		rust.NewAuditBinaryCataloger(),
		rust.NewCargoLockCataloger(),
		sbom.NewSBOMCataloger(),
		swift.NewCocoapodsCataloger(),
	}, cfg.Catalogers)
}

func RequestedAllCatalogers(cfg Config) bool {
	for _, enableCatalogerPattern := range cfg.Catalogers {
		if enableCatalogerPattern == AllCatalogersPattern {
			return true
		}
	}
	return false
}

func filterCatalogers(catalogers []pkg.Cataloger, enabledCatalogerPatterns []string) []pkg.Cataloger {
	// if cataloger is not set, all applicable catalogers are enabled by default
	if len(enabledCatalogerPatterns) == 0 {
		return catalogers
	}
	for _, enableCatalogerPattern := range enabledCatalogerPatterns {
		if enableCatalogerPattern == AllCatalogersPattern {
			return catalogers
		}
	}
	var keepCatalogers []pkg.Cataloger
	for _, cataloger := range catalogers {
		if contains(enabledCatalogerPatterns, cataloger.Name()) {
			keepCatalogers = append(keepCatalogers, cataloger)
			continue
		}
		log.Infof("skipping cataloger %q", cataloger.Name())
	}
	return keepCatalogers
}

func contains(enabledPartial []string, catalogerName string) bool {
	catalogerName = strings.TrimSuffix(catalogerName, "-cataloger")
	for _, partial := range enabledPartial {
		partial = strings.TrimSuffix(partial, "-cataloger")
		if partial == "" {
			continue
		}
		if hasFullWord(partial, catalogerName) {
			return true
		}
	}
	return false
}

func hasFullWord(targetPhrase, candidate string) bool {
	if targetPhrase == "cataloger" || targetPhrase == "" {
		return false
	}
	start := strings.Index(candidate, targetPhrase)
	if start == -1 {
		return false
	}

	if start > 0 && candidate[start-1] != '-' {
		return false
	}

	end := start + len(targetPhrase)
	if end < len(candidate) && candidate[end] != '-' {
		return false
	}
	return true
}
