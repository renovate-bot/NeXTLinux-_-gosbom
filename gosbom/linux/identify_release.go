package linux

import (
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/acobaugh/osrelease"
	"github.com/google/go-cmp/cmp"

	"github.com/nextlinux/gosbom/gosbom/file"
	"github.com/nextlinux/gosbom/internal"
	"github.com/nextlinux/gosbom/internal/log"
)

// returns a distro or nil
type parseFunc func(string) (*Release, error)

type parseEntry struct {
	path string
	fn   parseFunc
}

var identityFiles = []parseEntry{
	{
		// most distros provide a link at this location
		path: "/etc/os-release",
		fn:   parseOsRelease,
	},
	{
		// standard location for rhel & debian distros
		path: "/usr/lib/os-release",
		fn:   parseOsRelease,
	},
	{
		// check for centos:6
		path: "/etc/system-release-cpe",
		fn:   parseSystemReleaseCPE,
	},
	{
		// last ditch effort for determining older centos version distro information
		path: "/etc/redhat-release",
		fn:   parseRedhatRelease,
	},
	// /////////////////////////////////////////////////////////////////////////////////////////////////////
	// IMPORTANT! checking busybox must be last since other distros contain the busybox binary
	{
		// check for busybox
		path: "/bin/busybox",
		fn:   parseBusyBox,
	},
	// /////////////////////////////////////////////////////////////////////////////////////////////////////
}

// IdentifyRelease parses distro-specific files to discover and raise linux distribution release details.
func IdentifyRelease(resolver file.Resolver) *Release {
	logger := log.Nested("operation", "identify-release")
	for _, entry := range identityFiles {
		locations, err := resolver.FilesByPath(entry.path)
		if err != nil {
			logger.WithFields("error", err, "path", entry.path).Trace("unable to get path")
			continue
		}

		for _, location := range locations {
			contentReader, err := resolver.FileContentsByLocation(location)
			if err != nil {
				logger.WithFields("error", err, "path", location.RealPath).Trace("unable to get contents")
				continue
			}

			content, err := io.ReadAll(contentReader)
			internal.CloseAndLogError(contentReader, location.VirtualPath)
			if err != nil {
				logger.WithFields("error", err, "path", location.RealPath).Trace("unable to read contents")
				continue
			}

			release, err := entry.fn(string(content))
			if err != nil {
				logger.WithFields("error", err, "path", location.RealPath).Trace("unable to parse contents")
				continue
			}

			if release != nil {
				return release
			}
		}
	}

	return nil
}

func parseOsRelease(contents string) (*Release, error) {
	values, err := osrelease.ReadString(contents)
	if err != nil {
		return nil, fmt.Errorf("unable to read os-release file: %w", err)
	}

	var idLike []string
	for _, s := range strings.Split(values["ID_LIKE"], " ") {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		idLike = append(idLike, s)
	}

	r := Release{
		PrettyName:       values["PRETTY_NAME"],
		Name:             values["NAME"],
		ID:               values["ID"],
		IDLike:           idLike,
		Version:          values["VERSION"],
		VersionID:        values["VERSION_ID"],
		VersionCodename:  values["VERSION_CODENAME"],
		BuildID:          values["BUILD_ID"],
		ImageID:          values["IMAGE_ID"],
		ImageVersion:     values["IMAGE_VERSION"],
		Variant:          values["VARIANT"],
		VariantID:        values["VARIANT_ID"],
		HomeURL:          values["HOME_URL"],
		SupportURL:       values["SUPPORT_URL"],
		BugReportURL:     values["BUG_REPORT_URL"],
		PrivacyPolicyURL: values["PRIVACY_POLICY_URL"],
		CPEName:          values["CPE_NAME"],
		SupportEnd:       values["SUPPORT_END"],
	}

	// don't allow for empty contents to result in a Release object being created
	if cmp.Equal(r, Release{}) {
		return nil, nil
	}

	return &r, nil
}

var busyboxVersionMatcher = regexp.MustCompile(`BusyBox v[\d.]+`)

func parseBusyBox(contents string) (*Release, error) {
	matches := busyboxVersionMatcher.FindAllString(contents, -1)
	for _, match := range matches {
		parts := strings.Split(match, " ")
		version := strings.ReplaceAll(parts[1], "v", "")

		return simpleRelease(match, "busybox", version, ""), nil
	}
	return nil, nil
}

// example CPE: cpe:/o:centos:linux:6:GA
var systemReleaseCpeMatcher = regexp.MustCompile(`cpe:\/o:(.*?):.*?:(.*?):.*?$`)

// parseSystemReleaseCPE parses the older centos (6) file to determine distro metadata
func parseSystemReleaseCPE(contents string) (*Release, error) {
	matches := systemReleaseCpeMatcher.FindAllStringSubmatch(contents, -1)
	for _, match := range matches {
		if len(match) < 3 {
			continue
		}
		return simpleRelease(match[1], strings.ToLower(match[1]), match[2], match[0]), nil
	}
	return nil, nil
}

// example: "CentOS release 6.10 (Final)"
var redhatReleaseMatcher = regexp.MustCompile(`(.*?)\srelease\s(\d\.\d+)`)

// parseRedhatRelease is a fallback parsing method for determining distro information in older redhat versions
func parseRedhatRelease(contents string) (*Release, error) {
	matches := redhatReleaseMatcher.FindAllStringSubmatch(contents, -1)
	for _, match := range matches {
		if len(match) < 3 {
			continue
		}
		return simpleRelease(match[1], strings.ToLower(match[1]), match[2], ""), nil
	}
	return nil, nil
}

func simpleRelease(prettyName, name, version, cpe string) *Release {
	return &Release{
		PrettyName: prettyName,
		Name:       name,
		ID:         name,
		IDLike:     []string{name},
		Version:    version,
		VersionID:  version,
		CPEName:    cpe,
	}
}
