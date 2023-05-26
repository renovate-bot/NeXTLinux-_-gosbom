/*
Package portage provides a concrete Cataloger implementation for Gentoo Portage.
*/
package portage

import (
	"github.com/nextlinux/gosbom/syft/pkg/cataloger/generic"
)

func NewPortageCataloger() *generic.Cataloger {
	return generic.NewCataloger("portage-cataloger").
		WithParserByGlobs(parsePortageContents, "**/var/db/pkg/*/*/CONTENTS")
}
