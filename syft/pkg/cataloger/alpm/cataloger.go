package alpm

import (
	"github.com/nextlinux/gosbom/syft/pkg"
	"github.com/nextlinux/gosbom/syft/pkg/cataloger/generic"
)

const catalogerName = "alpmdb-cataloger"

func NewAlpmdbCataloger() *generic.Cataloger {
	return generic.NewCataloger(catalogerName).
		WithParserByGlobs(parseAlpmDB, pkg.AlpmDBGlob)
}
