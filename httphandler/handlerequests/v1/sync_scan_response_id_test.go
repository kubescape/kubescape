package v1

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/kubescape/kubescape/v4/core/cautils"
	utilsapisv1 "github.com/kubescape/opa-utils/httpserver/apis/v1"
	utilsmetav1 "github.com/kubescape/opa-utils/httpserver/meta/v1"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestScanSyncResponseIncludesGeneratedID(t *testing.T) {
	tests := []struct {
		name       string
		scanErr    error
		wantStatus int
		wantType   utilsapisv1.ScanResponseType
	}{
		{
			name:       "successful scan",
			wantStatus: http.StatusOK,
			wantType:   utilsapisv1.ResultsV1ScanResponseType,
		},
		{
			name:       "failed scan",
			scanErr:    errors.New("deterministic scan failure"),
			wantStatus: http.StatusInternalServerError,
			wantType:   utilsapisv1.ErrorScanResponseType,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			withTempOutputDirs(t)

			originalScanImpl := scanImpl
			t.Cleanup(func() { scanImpl = originalScanImpl })

			generatedID := make(chan string, 1)
			scanImpl = func(_ context.Context, _ *cautils.ScanInfo, _ []cautils.PolicyIdentifier, scanID string, _ bool) (*reporthandlingv2.PostureReport, error) {
				generatedID <- scanID
				if tt.scanErr != nil {
					return nil, tt.scanErr
				}
				if err := os.WriteFile(filepath.Join(OutputDir, scanID+".json"), []byte("{}"), 0o600); err != nil {
					return nil, err
				}
				return nil, nil
			}

			h := NewHTTPHandler(false)
			w := httptest.NewRecorder()
			h.Scan(w, httptest.NewRequest(http.MethodPost, "/scan?wait=true&keep=true", strings.NewReader("{}")))

			require.Equal(t, tt.wantStatus, w.Code, "body=%s", w.Body.String())
			var response utilsmetav1.Response
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
			assert.Equal(t, tt.wantType, response.Type)

			wantID := <-generatedID
			require.NoError(t, uuid.Validate(wantID), "handler-generated scan ID must be a UUID")
			assert.Equal(t, wantID, response.ID, "synchronous response must retain the generated scan ID")
		})
	}
}
