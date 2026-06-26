package reportcrypto

import (
	"fmt"

	"github.com/kubescape/opa-utils/reporthandling"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
)

// DEKFromMetadata extracts and unwraps the DEK stored in
// EncryptionMetadata using the supplied master key.
//
// This is the first step of the decryption workflow:
//
//	EncryptionMetadata.EncryptedDEK
//	          ↓
//	     UnwrapDEK()
//	          ↓
//	           DEK
func DEKFromMetadata(
	metadata *reporthandlingv2.Metadata,
	masterKey []byte,
) ([]byte, error) {

	if metadata == nil {
		return nil, fmt.Errorf("metadata is nil")
	}

	if metadata.EncryptionMetadata == nil {
		return nil, fmt.Errorf("encryption metadata not found")
	}

	if metadata.EncryptionMetadata.EncryptedDEK == "" {
		return nil, fmt.Errorf("encrypted DEK not found")
	}

	return UnwrapDEK(
		metadata.EncryptionMetadata.EncryptedDEK,
		masterKey,
	)
}

// DecryptRepoContextMetadata decrypts all repository context fields
// previously encrypted by ApplyEncrypted.
//
// This operation mutates the supplied metadata object in place.
//
// Current fields:
//
//   - Repo
//   - Owner
//   - Branch
//   - RemoteURL
//   - LastCommit.Message
//
// Additional fields can be added as encryption coverage expands.
func DecryptRepoContextMetadata(
	metadata *reporthandlingv2.Metadata,
	masterKey []byte,
) error {

	dek, err := DEKFromMetadata(
		metadata,
		masterKey,
	)
	if err != nil {
		return err
	}

	defer func() {
		for i := range dek {
			dek[i] = 0
		}
	}()

	repoMetadata :=
		metadata.ContextMetadata.RepoContextMetadata

	if repoMetadata == nil {
		return nil
	}

	if repoMetadata.Repo != "" {
		repoMetadata.Repo, err =
			DecryptString(repoMetadata.Repo, dek)
		if err != nil {
			return fmt.Errorf(
				"failed to decrypt repo: %w",
				err,
			)
		}
	}

	if repoMetadata.Owner != "" {
		repoMetadata.Owner, err =
			DecryptString(repoMetadata.Owner, dek)
		if err != nil {
			return fmt.Errorf(
				"failed to decrypt owner: %w",
				err,
			)
		}
	}

	if repoMetadata.Branch != "" {
		repoMetadata.Branch, err =
			DecryptString(repoMetadata.Branch, dek)
		if err != nil {
			return fmt.Errorf(
				"failed to decrypt branch: %w",
				err,
			)
		}
	}

	if repoMetadata.DefaultBranch != "" {
		repoMetadata.DefaultBranch, err =
			DecryptString(
				repoMetadata.DefaultBranch,
				dek,
			)
		if err != nil {
			return fmt.Errorf(
				"failed to decrypt default branch: %w",
				err,
			)
		}
	}

	if repoMetadata.RemoteURL != "" {
		repoMetadata.RemoteURL, err =
			DecryptString(
				repoMetadata.RemoteURL,
				dek,
			)
		if err != nil {
			return fmt.Errorf(
				"failed to decrypt remoteURL: %w",
				err,
			)
		}
	}

	if repoMetadata.LocalRootPath != "" {
		repoMetadata.LocalRootPath, err =
			DecryptString(
				repoMetadata.LocalRootPath,
				dek,
			)
		if err != nil {
			return fmt.Errorf(
				"failed to decrypt localRootPath: %w",
				err,
			)
		}
	}

	if err := decryptLastCommit(
		&repoMetadata.LastCommit,
		dek,
	); err != nil {
		return err
	}

	return nil
}

// decryptLastCommit decrypts all commit metadata fields that may have
// been encrypted by transformLastCommit.
//
// This operation mutates the supplied LastCommit object in place.
func decryptLastCommit(
	commit *reporthandling.LastCommit,
	dek []byte,
) error {
	if commit == nil {
		return nil
	}

	var err error

	if commit.Hash != "" {
		commit.Hash, err = DecryptString(
			commit.Hash,
			dek,
		)
		if err != nil {
			return fmt.Errorf(
				"failed to decrypt commit hash: %w",
				err,
			)
		}
	}

	if commit.CommitterName != "" {
		commit.CommitterName, err = DecryptString(
			commit.CommitterName,
			dek,
		)
		if err != nil {
			return fmt.Errorf(
				"failed to decrypt committer name: %w",
				err,
			)
		}
	}

	if commit.CommitterEmail != "" {
		commit.CommitterEmail, err = DecryptString(
			commit.CommitterEmail,
			dek,
		)
		if err != nil {
			return fmt.Errorf(
				"failed to decrypt committer email: %w",
				err,
			)
		}
	}

	if commit.Message != "" {
		commit.Message, err = DecryptString(
			commit.Message,
			dek,
		)
		if err != nil {
			return fmt.Errorf(
				"failed to decrypt commit message: %w",
				err,
			)
		}
	}

	return nil
}

// DecryptResourceSource decrypts source metadata previously encrypted
// by transformResourceSource.
//
// This operation mutates the supplied Source object in place.
//
// Current coverage:
//
//   - Path
//   - RelativePath
//   - HelmPath
//   - HelmChartName
//   - HelmTemplateFile
//   - HelmValuesPaths
//   - KustomizeDirectoryName
//   - LastCommit.Hash
//   - LastCommit.CommitterName
//   - LastCommit.CommitterEmail
//   - LastCommit.Message
func DecryptResourceSource(
	source *reporthandling.Source,
	dek []byte,
) error {
	if source == nil {
		return nil
	}

	var err error

	if source.Path != "" {
		source.Path, err = DecryptString(
			source.Path,
			dek,
		)
		if err != nil {
			return fmt.Errorf(
				"failed to decrypt path: %w",
				err,
			)
		}
	}

	if source.RelativePath != "" {
		source.RelativePath, err = DecryptString(
			source.RelativePath,
			dek,
		)
		if err != nil {
			return fmt.Errorf(
				"failed to decrypt relative path: %w",
				err,
			)
		}
	}

	if source.HelmPath != "" {
		source.HelmPath, err = DecryptString(
			source.HelmPath,
			dek,
		)
		if err != nil {
			return fmt.Errorf(
				"failed to decrypt helm path: %w",
				err,
			)
		}
	}

	if source.HelmChartName != "" {
		source.HelmChartName, err = DecryptString(
			source.HelmChartName,
			dek,
		)
		if err != nil {
			return fmt.Errorf(
				"failed to decrypt helm chart name: %w",
				err,
			)
		}
	}

	if source.HelmTemplateFile != "" {
		source.HelmTemplateFile, err = DecryptString(
			source.HelmTemplateFile,
			dek,
		)
		if err != nil {
			return fmt.Errorf(
				"failed to decrypt helm template file: %w",
				err,
			)
		}
	}

	if source.KustomizeDirectoryName != "" {
		source.KustomizeDirectoryName, err = DecryptString(
			source.KustomizeDirectoryName,
			dek,
		)
		if err != nil {
			return fmt.Errorf(
				"failed to decrypt kustomize directory name: %w",
				err,
			)
		}
	}

	for i := range source.HelmValuesPaths {
		if source.HelmValuesPaths[i] == "" {
			continue
		}

		source.HelmValuesPaths[i], err = DecryptString(
			source.HelmValuesPaths[i],
			dek,
		)
		if err != nil {
			return fmt.Errorf(
				"failed to decrypt helm values path[%d]: %w",
				i,
				err,
			)
		}
	}

	if err := decryptLastCommit(
		&source.LastCommit,
		dek,
	); err != nil {
		return err
	}

	return nil
}
