/*
Package swift provides a concrete Cataloger implementation for Podfile.lock files.
*/
package swift

import (
	"github.com/nextlinux/gosbom/gosbom/pkg/cataloger/generic"
)

// NewCocoapodsCataloger returns a new Swift Cocoapods lock file cataloger object.
func NewCocoapodsCataloger() *generic.Cataloger {
	return generic.NewCataloger("cocoapods-cataloger").
		WithParserByGlobs(parsePodfileLock, "**/Podfile.lock")
}
