package reportcrypto

import (
	"fmt"

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
			DecryptString(repoMetadata.RemoteURL, dek)
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

	if repoMetadata.LastCommit.Hash != "" {
		repoMetadata.LastCommit.Hash, err =
			DecryptString(
				repoMetadata.LastCommit.Hash,
				dek,
			)
		if err != nil {
			return fmt.Errorf(
				"failed to decrypt commit hash: %w",
				err,
			)
		}
	}

	if repoMetadata.LastCommit.CommitterName != "" {
		repoMetadata.LastCommit.CommitterName, err =
			DecryptString(
				repoMetadata.LastCommit.CommitterName,
				dek,
			)
		if err != nil {
			return fmt.Errorf(
				"failed to decrypt committer name: %w",
				err,
			)
		}
	}

	if repoMetadata.LastCommit.CommitterEmail != "" {
		repoMetadata.LastCommit.CommitterEmail, err =
			DecryptString(
				repoMetadata.LastCommit.CommitterEmail,
				dek,
			)
		if err != nil {
			return fmt.Errorf(
				"failed to decrypt committer email: %w",
				err,
			)
		}
	}

	if repoMetadata.LastCommit.Message != "" {
		repoMetadata.LastCommit.Message, err =
			DecryptString(
				repoMetadata.LastCommit.Message,
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
