package v1

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"testing"

	"github.com/armosec/utils-go/boolutils"
	logger "github.com/kubescape/go-logger"
	utilsmetav1 "github.com/kubescape/opa-utils/httpserver/meta/v1"
	"github.com/stretchr/testify/assert"
)

func TestGetScanParamsFromRequest(t *testing.T) {
	{
		body := utilsmetav1.PostScanRequest{
			Submit:      boolutils.BoolPointer(true),
			HostScanner: boolutils.BoolPointer(true),
			Account:     "aaaaaaaaaa",
		}

		jsonBytes, err := json.Marshal(body)
		assert.NoError(t, err)

		u := url.URL{
			Scheme:   "http",
			Host:     "bla",
			Path:     "bla",
			RawQuery: "wait=true&keep=true",
		}
		request, err := http.NewRequest(http.MethodPost, u.String(), bytes.NewReader(jsonBytes))
		assert.NoError(t, err)

		scanID := "ccccccc"

		req, err := getScanParamsFromRequest(request, scanID)
		assert.NoError(t, err)
		assert.Equal(t, scanID, req.scanID)
		assert.True(t, req.scanQueryParams.KeepResults)
		assert.True(t, req.scanQueryParams.ReturnResults)
		assert.True(t, req.scanInfo.HostSensorEnabled.GetBool())
		assert.True(t, req.scanInfo.Submit)
		assert.Equal(t, "aaaaaaaaaa", req.scanInfo.AccountID)
	}

	{
		body := utilsmetav1.PostScanRequest{
			Submit:      boolutils.BoolPointer(false),
			HostScanner: boolutils.BoolPointer(false),
			Account:     "aaaaaaaaaa",
		}

		jsonBytes, err := json.Marshal(body)
		assert.NoError(t, err)

		u := url.URL{
			Scheme: "http",
			Host:   "bla",
			Path:   "bla",
		}
		request, err := http.NewRequest(http.MethodPost, u.String(), bytes.NewReader(jsonBytes))
		assert.NoError(t, err)

		scanID := "ccccccc"

		req, err := getScanParamsFromRequest(request, scanID)
		assert.NoError(t, err)
		assert.Equal(t, scanID, req.scanID)
		assert.False(t, req.scanQueryParams.KeepResults)
		assert.False(t, req.scanQueryParams.ReturnResults)
		assert.False(t, req.scanInfo.HostSensorEnabled.GetBool())
		assert.False(t, req.scanInfo.Submit)
		assert.Equal(t, "aaaaaaaaaa", req.scanInfo.AccountID)
	}
}

// TestNoSecretsInLogs ensures that sensitive fields (accessKey, account) sent in
// a scan request body are never written to the application log stream.
func TestNoSecretsInLogs(t *testing.T) {
	const (
		secretAccessKey = "s3cr3t-access-key-value"
		secretAccount   = "secret-account-id-12345"
	)

	rPipe, wPipe, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}

	oldWriter := logger.L().GetWriter()
	logger.L().SetWriter(wPipe)
	t.Cleanup(func() { logger.L().SetWriter(oldWriter) })

	body := utilsmetav1.PostScanRequest{
		Account:   secretAccount,
		AccessKey: secretAccessKey,
	}
	jsonBytes, err := json.Marshal(body)
	assert.NoError(t, err)

	u := url.URL{Scheme: "http", Host: "test", Path: "/v1/scan"}
	req, err := http.NewRequest(http.MethodPost, u.String(), bytes.NewReader(jsonBytes))
	assert.NoError(t, err)

	_, err = getScanParamsFromRequest(req, "test-scan-id")
	assert.NoError(t, err)

	wPipe.Close()
	logOutput, err := io.ReadAll(rPipe)
	assert.NoError(t, err)
	rPipe.Close()

	// Sanity-check that the logger output was actually captured.
	assert.Contains(t, string(logOutput), "test-scan-id", "expected scan log line was not captured")
	assert.NotContains(t, string(logOutput), secretAccessKey, "accessKey must not appear in logs")
	assert.NotContains(t, string(logOutput), secretAccount, "account must not appear in logs")
}
