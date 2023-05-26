package cpe

import "github.com/nextlinux/gosbom/gosbom/pkg"

func candidateVendorsForRPM(p pkg.Package) fieldCandidateSet {
	metadata, ok := p.Metadata.(pkg.RpmMetadata)
	if !ok {
		return nil
	}

	vendors := newFieldCandidateSet()

	if metadata.Vendor != "" {
		vendors.add(fieldCandidate{
			value:                 normalizeName(metadata.Vendor),
			disallowSubSelections: true,
		})
	}

	return vendors
}
