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

	encryptedDefaultBranch, err := EncryptString(
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

	encryptedCommitterName, err := EncryptString(
		"John Doe",
		dek,
	)
	require.NoError(t, err)

	encryptedCommitterEmail, err := EncryptString(
		"john@example.com",
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
				DefaultBranch: encryptedDefaultBranch,
				RemoteURL:     encryptedRemoteURL,
				LocalRootPath: encryptedLocalRootPath,
				LastCommit: reporthandling.LastCommit{
					Hash:           encryptedCommitHash,
					CommitterName:  encryptedCommitterName,
					CommitterEmail: encryptedCommitterEmail,
					Message:        encryptedCommitMessage,
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
		"main",
		repoMetadata.DefaultBranch,
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
		"John Doe",
		repoMetadata.LastCommit.CommitterName,
	)

	assert.Equal(
		t,
		"john@example.com",
		repoMetadata.LastCommit.CommitterEmail,
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

func TestDecryptResourceSource_RoundTrip(
	t *testing.T,
) {
	dek, err := GenerateDEK()
	require.NoError(t, err)

	encryptedPath, err := EncryptString(
		"/workspace/private/app.yaml",
		dek,
	)
	require.NoError(t, err)

	encryptedRelativePath, err := EncryptString(
		"services/payments/app.yaml",
		dek,
	)
	require.NoError(t, err)

	encryptedHelmPath, err := EncryptString(
		"charts/internal",
		dek,
	)
	require.NoError(t, err)

	encryptedChartName, err := EncryptString(
		"payments-service",
		dek,
	)
	require.NoError(t, err)

	encryptedTemplateFile, err := EncryptString(
		"templates/deployment.yaml",
		dek,
	)
	require.NoError(t, err)

	encryptedKustomizeDir, err := EncryptString(
		"prod-overlay",
		dek,
	)
	require.NoError(t, err)

	encryptedValue1, err := EncryptString(
		"database.password",
		dek,
	)
	require.NoError(t, err)

	encryptedValue2, err := EncryptString(
		"redis.password",
		dek,
	)
	require.NoError(t, err)

	encryptedCommitHash, err := EncryptString(
		"abc123",
		dek,
	)
	require.NoError(t, err)

	encryptedCommitterName, err := EncryptString(
		"John Doe",
		dek,
	)
	require.NoError(t, err)

	encryptedCommitterEmail, err := EncryptString(
		"john@example.com",
		dek,
	)
	require.NoError(t, err)

	encryptedCommitMessage, err := EncryptString(
		"internal change",
		dek,
	)
	require.NoError(t, err)

	source := &reporthandling.Source{
		Path:                   encryptedPath,
		RelativePath:           encryptedRelativePath,
		HelmPath:               encryptedHelmPath,
		HelmChartName:          encryptedChartName,
		HelmTemplateFile:       encryptedTemplateFile,
		KustomizeDirectoryName: encryptedKustomizeDir,
		HelmValuesPaths: []string{
			encryptedValue1,
			encryptedValue2,
		},
		LastCommit: reporthandling.LastCommit{
			Hash:           encryptedCommitHash,
			CommitterName:  encryptedCommitterName,
			CommitterEmail: encryptedCommitterEmail,
			Message:        encryptedCommitMessage,
		},
	}

	err = DecryptResourceSource(
		source,
		dek,
	)

	require.NoError(t, err)

	assert.Equal(
		t,
		"/workspace/private/app.yaml",
		source.Path,
	)

	assert.Equal(
		t,
		"services/payments/app.yaml",
		source.RelativePath,
	)

	assert.Equal(
		t,
		"charts/internal",
		source.HelmPath,
	)

	assert.Equal(
		t,
		"payments-service",
		source.HelmChartName,
	)

	assert.Equal(
		t,
		"templates/deployment.yaml",
		source.HelmTemplateFile,
	)

	assert.Equal(
		t,
		"prod-overlay",
		source.KustomizeDirectoryName,
	)

	assert.Equal(
		t,
		[]string{
			"database.password",
			"redis.password",
		},
		source.HelmValuesPaths,
	)

	assert.Equal(
		t,
		"abc123",
		source.LastCommit.Hash,
	)

	assert.Equal(
		t,
		"John Doe",
		source.LastCommit.CommitterName,
	)

	assert.Equal(
		t,
		"john@example.com",
		source.LastCommit.CommitterEmail,
	)

	assert.Equal(
		t,
		"internal change",
		source.LastCommit.Message,
	)
}

func TestDecryptResourceSource_Nil(
	t *testing.T,
) {
	err := DecryptResourceSource(
		nil,
		make([]byte, 32),
	)

	require.NoError(t, err)
}
