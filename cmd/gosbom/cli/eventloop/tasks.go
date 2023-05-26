package eventloop

import (
	"crypto"
	"fmt"

	syft "github.com/nextlinux/gosbom/gosbom"
	"github.com/nextlinux/gosbom/gosbom/artifact"
	"github.com/nextlinux/gosbom/gosbom/file"
	"github.com/nextlinux/gosbom/gosbom/file/cataloger/filecontent"
	"github.com/nextlinux/gosbom/gosbom/file/cataloger/filedigest"
	"github.com/nextlinux/gosbom/gosbom/file/cataloger/filemetadata"
	"github.com/nextlinux/gosbom/gosbom/file/cataloger/secrets"
	"github.com/nextlinux/gosbom/gosbom/sbom"
	"github.com/nextlinux/gosbom/gosbom/source"
	"github.com/nextlinux/gosbom/internal/config"
)

type Task func(*sbom.Artifacts, *source.Source) ([]artifact.Relationship, error)

func Tasks(app *config.Application) ([]Task, error) {
	var tasks []Task

	generators := []func(app *config.Application) (Task, error){
		generateCatalogPackagesTask,
		generateCatalogFileMetadataTask,
		generateCatalogFileDigestsTask,
		generateCatalogSecretsTask,
		generateCatalogContentsTask,
	}

	for _, generator := range generators {
		task, err := generator(app)
		if err != nil {
			return nil, err
		}

		if task != nil {
			tasks = append(tasks, task)
		}
	}

	return tasks, nil
}

func generateCatalogPackagesTask(app *config.Application) (Task, error) {
	if !app.Package.Cataloger.Enabled {
		return nil, nil
	}

	task := func(results *sbom.Artifacts, src *source.Source) ([]artifact.Relationship, error) {
		packageCatalog, relationships, theDistro, err := syft.CatalogPackages(src, app.ToCatalogerConfig())

		results.Packages = packageCatalog
		results.LinuxDistribution = theDistro

		return relationships, err
	}

	return task, nil
}

func generateCatalogFileMetadataTask(app *config.Application) (Task, error) {
	if !app.FileMetadata.Cataloger.Enabled {
		return nil, nil
	}

	metadataCataloger := filemetadata.NewCataloger()

	task := func(results *sbom.Artifacts, src *source.Source) ([]artifact.Relationship, error) {
		resolver, err := src.FileResolver(app.FileMetadata.Cataloger.ScopeOpt)
		if err != nil {
			return nil, err
		}

		result, err := metadataCataloger.Catalog(resolver)
		if err != nil {
			return nil, err
		}
		results.FileMetadata = result
		return nil, nil
	}

	return task, nil
}

func generateCatalogFileDigestsTask(app *config.Application) (Task, error) {
	if !app.FileMetadata.Cataloger.Enabled {
		return nil, nil
	}

	supportedHashAlgorithms := make(map[string]crypto.Hash)
	for _, h := range []crypto.Hash{
		crypto.MD5,
		crypto.SHA1,
		crypto.SHA256,
	} {
		supportedHashAlgorithms[file.DigestAlgorithmName(h)] = h
	}

	var hashes []crypto.Hash
	for _, hashStr := range app.FileMetadata.Digests {
		name := file.CleanDigestAlgorithmName(hashStr)
		hashObj, ok := supportedHashAlgorithms[name]
		if !ok {
			return nil, fmt.Errorf("unsupported hash algorithm: %s", hashStr)
		}
		hashes = append(hashes, hashObj)
	}

	digestsCataloger := filedigest.NewCataloger(hashes)

	task := func(results *sbom.Artifacts, src *source.Source) ([]artifact.Relationship, error) {
		resolver, err := src.FileResolver(app.FileMetadata.Cataloger.ScopeOpt)
		if err != nil {
			return nil, err
		}

		result, err := digestsCataloger.Catalog(resolver)
		if err != nil {
			return nil, err
		}
		results.FileDigests = result
		return nil, nil
	}

	return task, nil
}

func generateCatalogSecretsTask(app *config.Application) (Task, error) {
	if !app.Secrets.Cataloger.Enabled {
		return nil, nil
	}

	patterns, err := secrets.GenerateSearchPatterns(secrets.DefaultSecretsPatterns, app.Secrets.AdditionalPatterns, app.Secrets.ExcludePatternNames)
	if err != nil {
		return nil, err
	}

	secretsCataloger, err := secrets.NewCataloger(patterns, app.Secrets.RevealValues, app.Secrets.SkipFilesAboveSize) //nolint:staticcheck
	if err != nil {
		return nil, err
	}

	task := func(results *sbom.Artifacts, src *source.Source) ([]artifact.Relationship, error) {
		resolver, err := src.FileResolver(app.Secrets.Cataloger.ScopeOpt)
		if err != nil {
			return nil, err
		}

		result, err := secretsCataloger.Catalog(resolver)
		if err != nil {
			return nil, err
		}
		results.Secrets = result
		return nil, nil
	}

	return task, nil
}

func generateCatalogContentsTask(app *config.Application) (Task, error) {
	if !app.FileContents.Cataloger.Enabled {
		return nil, nil
	}

	contentsCataloger, err := filecontent.NewCataloger(app.FileContents.Globs, app.FileContents.SkipFilesAboveSize) //nolint:staticcheck
	if err != nil {
		return nil, err
	}

	task := func(results *sbom.Artifacts, src *source.Source) ([]artifact.Relationship, error) {
		resolver, err := src.FileResolver(app.FileContents.Cataloger.ScopeOpt)
		if err != nil {
			return nil, err
		}

		result, err := contentsCataloger.Catalog(resolver)
		if err != nil {
			return nil, err
		}
		results.FileContents = result
		return nil, nil
	}

	return task, nil
}

func RunTask(t Task, a *sbom.Artifacts, src *source.Source, c chan<- artifact.Relationship, errs chan<- error) {
	defer close(c)

	relationships, err := t(a, src)
	if err != nil {
		errs <- err
		return
	}

	for _, relationship := range relationships {
		c <- relationship
	}
}
