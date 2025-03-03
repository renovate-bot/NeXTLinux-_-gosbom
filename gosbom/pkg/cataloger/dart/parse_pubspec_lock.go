package dart

import (
	"fmt"
	"net/url"
	"sort"

	"gopkg.in/yaml.v2"

	"github.com/nextlinux/gosbom/gosbom/artifact"
	"github.com/nextlinux/gosbom/gosbom/file"
	"github.com/nextlinux/gosbom/gosbom/pkg"
	"github.com/nextlinux/gosbom/gosbom/pkg/cataloger/generic"
	"github.com/nextlinux/gosbom/internal/log"
)

var _ generic.Parser = parsePubspecLock

const defaultPubRegistry string = "https://pub.dartlang.org"

type pubspecLock struct {
	Packages map[string]pubspecLockPackage `yaml:"packages"`
	Sdks     map[string]string             `yaml:"sdks"`
}

type pubspecLockPackage struct {
	Dependency  string                 `yaml:"dependency" mapstructure:"dependency"`
	Description pubspecLockDescription `yaml:"description" mapstructure:"description"`
	Source      string                 `yaml:"source" mapstructure:"source"`
	Version     string                 `yaml:"version" mapstructure:"version"`
}

type pubspecLockDescription struct {
	Name        string `yaml:"name" mapstructure:"name"`
	URL         string `yaml:"url" mapstructure:"url"`
	Path        string `yaml:"path" mapstructure:"path"`
	Ref         string `yaml:"ref" mapstructure:"ref"`
	ResolvedRef string `yaml:"resolved-ref" mapstructure:"resolved-ref"`
}

func parsePubspecLock(_ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	var pkgs []pkg.Package

	dec := yaml.NewDecoder(reader)

	var p pubspecLock
	if err := dec.Decode(&p); err != nil {
		return nil, nil, fmt.Errorf("failed to parse pubspec.lock file: %w", err)
	}

	var names []string
	for name := range p.Packages {
		names = append(names, name)
	}

	// always ensure there is a stable ordering of packages
	sort.Strings(names)

	for _, name := range names {
		pubPkg := p.Packages[name]
		pkgs = append(pkgs,
			newPubspecLockPackage(
				name,
				pubPkg,
				reader.Location.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
			),
		)
	}

	return pkgs, nil, nil
}

func (p *pubspecLockPackage) getVcsURL() string {
	if p.Source == "git" {
		if p.Description.Path == "." {
			return fmt.Sprintf("%s@%s", p.Description.URL, p.Description.ResolvedRef)
		}

		return fmt.Sprintf("%s@%s#%s", p.Description.URL, p.Description.ResolvedRef, p.Description.Path)
	}

	return ""
}

func (p *pubspecLockPackage) getHostedURL() string {
	if p.Source == "hosted" && p.Description.URL != defaultPubRegistry {
		u, err := url.Parse(p.Description.URL)
		if err != nil {
			log.Debugf("Unable to parse registry url %w", err)
			return p.Description.URL
		}
		return u.Host
	}

	return ""
}
