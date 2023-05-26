package model

import (
	"github.com/nextlinux/gosbom/gosbom/file"
)

type Secrets struct {
	Location file.Coordinates    `json:"location"`
	Secrets  []file.SearchResult `json:"secrets"`
}
