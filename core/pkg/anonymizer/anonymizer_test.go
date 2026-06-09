package anonymizer

import (
	"testing"

	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/core/pkg/reportcrypto"
	"github.com/kubescape/kubescape/v3/core/pkg/resultshandling"
	"github.com/kubescape/opa-utils/reporthandling"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestApply(t *testing.T) {
	tests := []struct {
		name    string
		handler *resultshandling.ResultsHandler
	}{
		{
			name:    "nil handler should return without error",
			handler: nil,
		},
		{
			name:    "nil scan data should return without error",
			handler: &resultshandling.ResultsHandler{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.NotPanics(t, func() {
				err := Apply(test.handler)
				assert.NoError(t, err)
			})
		})
	}
}

func TestApplyEncrypted(t *testing.T) {
	dek, err := reportcrypto.GenerateDEK()
	require.NoError(t, err)

	handler := &resultshandling.ResultsHandler{
		ScanData: &cautils.OPASessionObj{
			Metadata: &reporthandlingv2.Metadata{
				ContextMetadata: reporthandlingv2.ContextMetadata{
					RepoContextMetadata: &reporthandlingv2.RepoContextMetadata{
						Repo:  "demo-repository",
						Owner: "demo-owner",
						LastCommit: reporthandling.LastCommit{
							Message: "demo commit",
						},
					},
				},
			},
		},
	}

	err = ApplyEncrypted(
		handler,
		dek,
	)
	require.NoError(t, err)

	repo := handler.ScanData.Metadata.ContextMetadata.RepoContextMetadata

	assert.Contains(
		t,
		repo.Repo,
		"ENC[AES256_GCM,",
	)

	assert.Contains(
		t,
		repo.Owner,
		"ENC[AES256_GCM,",
	)

	decryptedRepo, err := reportcrypto.DecryptString(
		repo.Repo,
		dek,
	)
	require.NoError(t, err)

	assert.Equal(
		t,
		"demo-repository",
		decryptedRepo,
	)

	assert.Contains(
		t,
		repo.LastCommit.Message,
		"ENC[AES256_GCM,",
	)

	decryptedMessage, err := reportcrypto.DecryptString(
		repo.LastCommit.Message,
		dek,
	)
	require.NoError(t, err)

	assert.Equal(
		t,
		"demo commit",
		decryptedMessage,
	)
}

func TestApplyEncrypted_InvalidDEK(t *testing.T) {
	handler := &resultshandling.ResultsHandler{
		ScanData: &cautils.OPASessionObj{},
	}

	err := ApplyEncrypted(
		handler,
		[]byte("bad"),
	)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid DEK length")
}
