package rpm

import (
	"fmt"
	"strconv"

	rpmdb "github.com/knqyf263/go-rpmdb/pkg"
	"github.com/sassoftware/go-rpmutils"

	"github.com/nextlinux/gosbom/gosbom/artifact"
	"github.com/nextlinux/gosbom/gosbom/file"
	"github.com/nextlinux/gosbom/gosbom/pkg"
	"github.com/nextlinux/gosbom/gosbom/pkg/cataloger/generic"
)

// parseRpm parses a single RPM
func parseRpm(_ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	rpm, err := rpmutils.ReadRpm(reader)
	if err != nil {
		return nil, nil, fmt.Errorf("RPM file found but unable to read: %s (%w)", reader.Location.RealPath, err)
	}

	nevra, err := rpm.Header.GetNEVRA()
	if err != nil {
		return nil, nil, err
	}

	licenses, _ := rpm.Header.GetStrings(rpmutils.LICENSE)
	sourceRpm, _ := rpm.Header.GetString(rpmutils.SOURCERPM)
	vendor, _ := rpm.Header.GetString(rpmutils.VENDOR)
	digestAlgorithm := getDigestAlgorithm(rpm.Header)
	size, _ := rpm.Header.InstalledSize()
	files, _ := rpm.Header.GetFiles()

	pd := parsedData{
		Licenses: pkg.NewLicensesFromLocation(reader.Location, licenses...),
		RpmMetadata: pkg.RpmMetadata{
			Name:      nevra.Name,
			Version:   nevra.Version,
			Epoch:     parseEpoch(nevra.Epoch),
			Arch:      nevra.Arch,
			Release:   nevra.Release,
			SourceRpm: sourceRpm,
			Vendor:    vendor,
			Size:      int(size),
			Files:     mapFiles(files, digestAlgorithm),
		},
	}

	return []pkg.Package{newPackage(reader.Location, pd, nil)}, nil, nil
}

func getDigestAlgorithm(header *rpmutils.RpmHeader) string {
	digestAlgorithm, _ := header.GetString(rpmutils.FILEDIGESTALGO)
	if digestAlgorithm != "" {
		return digestAlgorithm
	}
	digestAlgorithms, _ := header.GetUint32s(rpmutils.FILEDIGESTALGO)
	if len(digestAlgorithms) > 0 {
		digestAlgo := int(digestAlgorithms[0])
		return rpmutils.GetFileAlgoName(digestAlgo)
	}
	return ""
}

func mapFiles(files []rpmutils.FileInfo, digestAlgorithm string) []pkg.RpmdbFileRecord {
	var out []pkg.RpmdbFileRecord
	for _, f := range files {
		digest := file.Digest{}
		if f.Digest() != "" {
			digest = file.Digest{
				Algorithm: digestAlgorithm,
				Value:     f.Digest(),
			}
		}
		out = append(out, pkg.RpmdbFileRecord{
			Path:      f.Name(),
			Mode:      pkg.RpmdbFileMode(f.Mode()),
			Size:      int(f.Size()),
			Digest:    digest,
			UserName:  f.UserName(),
			GroupName: f.GroupName(),
			Flags:     rpmdb.FileFlags(f.Flags()).String(),
		})
	}
	return out
}

func parseEpoch(epoch string) *int {
	i, err := strconv.Atoi(epoch)
	if err != nil {
		return nil
	}
	return &i
}
