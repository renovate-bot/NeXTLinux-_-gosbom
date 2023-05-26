package generic

import (
	"github.com/nextlinux/gosbom/gosbom/artifact"
	"github.com/nextlinux/gosbom/gosbom/file"
	"github.com/nextlinux/gosbom/gosbom/linux"
	"github.com/nextlinux/gosbom/gosbom/pkg"
)

type Environment struct {
	LinuxRelease *linux.Release
}

type Parser func(file.Resolver, *Environment, file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error)
