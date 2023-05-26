package generic

import (
	"github.com/nextlinux/gosbom/syft/artifact"
	"github.com/nextlinux/gosbom/syft/file"
	"github.com/nextlinux/gosbom/syft/linux"
	"github.com/nextlinux/gosbom/syft/pkg"
)

type Environment struct {
	LinuxRelease *linux.Release
}

type Parser func(file.Resolver, *Environment, file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error)
