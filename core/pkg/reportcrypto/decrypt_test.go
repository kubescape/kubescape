package reportcrypto

import (
	"testing"

	reporthandling "github.com/kubescape/opa-utils/reporthandling"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDecryptRepoContextMetadata_RoundTrip(t *testing.T) {
	dek, err := GenerateDEK()
	require.NoError(t, err)

	masterKey, err := GenerateDEK()
	require.NoError(t, err)

	encryptedRepo, err := EncryptString(
		"demo-repository",
		dek,
	)
	require.NoError(t, err)

	encryptedOwner, err := EncryptString(
		"demo-owner",
		dek,
	)
	require.NoError(t, err)

	encryptedBranch, err := EncryptString(
		"main",
		dek,
	)
	require.NoError(t, err)

	encryptedRemoteURL, err := EncryptString(
		"https://github.com/example/repo",
		dek,
	)
	require.NoError(t, err)

	encryptedLocalRootPath, err := EncryptString(
		"/home/user/repository",
		dek,
	)
	require.NoError(t, err)

	encryptedCommitHash, err := EncryptString(
		"abc123def456",
		dek,
	)
	require.NoError(t, err)

	encryptedCommitMessage, err := EncryptString(
		"initial commit",
		dek,
	)
	require.NoError(t, err)

	wrappedDEK, err := WrapDEK(
		dek,
		masterKey,
	)
	require.NoError(t, err)

	metadata := &reporthandlingv2.Metadata{
		ContextMetadata: reporthandlingv2.ContextMetadata{
			RepoContextMetadata: &reporthandlingv2.RepoContextMetadata{
				Repo:          encryptedRepo,
				Owner:         encryptedOwner,
				Branch:        encryptedBranch,
				RemoteURL:     encryptedRemoteURL,
				LocalRootPath: encryptedLocalRootPath,
				LastCommit: reporthandling.LastCommit{
					Hash:    encryptedCommitHash,
					Message: encryptedCommitMessage,
				},
			},
		},
		EncryptionMetadata: &reporthandlingv2.EncryptionMetadata{
			Version:      "v1",
			DEKAlgorithm: "AES256_GCM",
			KEKAlgorithm: "AES256_GCM",
			EncryptedDEK: wrappedDEK,
		},
	}

	err = DecryptRepoContextMetadata(
		metadata,
		masterKey,
	)
	require.NoError(t, err)

	repoMetadata :=
		metadata.ContextMetadata.RepoContextMetadata

	assert.Equal(
		t,
		"demo-repository",
		repoMetadata.Repo,
	)

	assert.Equal(
		t,
		"demo-owner",
		repoMetadata.Owner,
	)

	assert.Equal(
		t,
		"main",
		repoMetadata.Branch,
	)

	assert.Equal(
		t,
		"https://github.com/example/repo",
		repoMetadata.RemoteURL,
	)

	assert.Equal(
		t,
		"/home/user/repository",
		repoMetadata.LocalRootPath,
	)

	assert.Equal(
		t,
		"abc123def456",
		repoMetadata.LastCommit.Hash,
	)

	assert.Equal(
		t,
		"initial commit",
		repoMetadata.LastCommit.Message,
	)
}

func TestDecryptRepoContextMetadata_WrongMasterKey(
	t *testing.T,
) {
	dek, err := GenerateDEK()
	require.NoError(t, err)

	masterKey, err := GenerateDEK()
	require.NoError(t, err)

	wrongMasterKey, err := GenerateDEK()
	require.NoError(t, err)

	encryptedRepo, err := EncryptString(
		"demo-repository",
		dek,
	)
	require.NoError(t, err)

	wrappedDEK, err := WrapDEK(
		dek,
		masterKey,
	)
	require.NoError(t, err)

	metadata := &reporthandlingv2.Metadata{
		ContextMetadata: reporthandlingv2.ContextMetadata{
			RepoContextMetadata: &reporthandlingv2.RepoContextMetadata{
				Repo: encryptedRepo,
			},
		},
		EncryptionMetadata: &reporthandlingv2.EncryptionMetadata{
			EncryptedDEK: wrappedDEK,
		},
	}

	err = DecryptRepoContextMetadata(
		metadata,
		wrongMasterKey,
	)

	require.Error(t, err)
}

func TestDEKFromMetadata_InvalidMasterKey(t *testing.T) {
	dek, err := GenerateDEK()
	require.NoError(t, err)

	masterKey, err := GenerateDEK()
	require.NoError(t, err)

	wrappedDEK, err := WrapDEK(
		dek,
		masterKey,
	)
	require.NoError(t, err)

	metadata := &reporthandlingv2.Metadata{
		EncryptionMetadata: &reporthandlingv2.EncryptionMetadata{
			EncryptedDEK: wrappedDEK,
		},
	}

	_, err = DEKFromMetadata(
		metadata,
		[]byte("bad"),
	)

	require.Error(t, err)
}

func TestDEKFromMetadata_NoEncryptionMetadata(t *testing.T) {
	metadata := &reporthandlingv2.Metadata{}

	_, err := DEKFromMetadata(
		metadata,
		make([]byte, 32),
	)

	require.Error(t, err)

	assert.Contains(
		t,
		err.Error(),
		"encryption metadata not found",
	)
}

func TestDecryptRepoContextMetadata_NoRepoMetadata(t *testing.T) {
	dek, err := GenerateDEK()
	require.NoError(t, err)

	masterKey, err := GenerateDEK()
	require.NoError(t, err)

	wrappedDEK, err := WrapDEK(
		dek,
		masterKey,
	)
	require.NoError(t, err)

	metadata := &reporthandlingv2.Metadata{
		EncryptionMetadata: &reporthandlingv2.EncryptionMetadata{
			EncryptedDEK: wrappedDEK,
		},
	}

	err = DecryptRepoContextMetadata(
		metadata,
		masterKey,
	)

	require.NoError(t, err)
}
