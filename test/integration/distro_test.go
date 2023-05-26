package integration

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/nextlinux/gosbom/syft/linux"
	"github.com/nextlinux/gosbom/syft/source"
)

func TestDistroImage(t *testing.T) {
	sbom, _ := catalogFixtureImage(t, "image-distro-id", source.SquashedScope, nil)

	expected := &linux.Release{
		PrettyName: "BusyBox v1.31.1",
		Name:       "busybox",
		ID:         "busybox",
		IDLike:     []string{"busybox"},
		Version:    "1.31.1",
		VersionID:  "1.31.1",
	}

	assert.Equal(t, expected, sbom.Artifacts.LinuxDistribution)
}
