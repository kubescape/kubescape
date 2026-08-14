package reporter

import (
	"context"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"sync"
	"testing"

	v1 "github.com/kubescape/backend/pkg/client/v1"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/prettylogger"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/core/cautils/getter"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mxStdio serializes the capture of os.Stderr or os.Stdout
var mxStdio sync.Mutex

type TenantConfigMock struct {
	clusterName string
	accountID   string
	accessKey   string
}

const testGeneratedAccountIDString = "6a1ff233-5297-4193-bb51-5d67bc841cbf"

func (tcm *TenantConfigMock) UpdateCachedConfig() error {
	return nil
}
func (tcm *TenantConfigMock) DeleteCachedConfig(ctx context.Context) error {
	return nil
}
func (tcm *TenantConfigMock) GetContextName() string {
	return tcm.clusterName
}
func (tcm *TenantConfigMock) GetAccountID() string {
	return tcm.accountID
}
func (tcm *TenantConfigMock) IsStorageEnabled() bool {
	return true
}
func (tcm *TenantConfigMock) GetConfigObj() *cautils.ConfigObj {
	return &cautils.ConfigObj{
		AccountID:   tcm.accountID,
		ClusterName: tcm.clusterName,
	}
}
func (tcm *TenantConfigMock) GetCloudReportURL() string {
	return ""
}
func (tcm *TenantConfigMock) GetCloudAPIURL() string {
	return ""
}

func (tcm *TenantConfigMock) GenerateAccountID() (string, error) {
	tcm.accountID = testGeneratedAccountIDString
	return testGeneratedAccountIDString, nil
}

func (tcm *TenantConfigMock) DeleteCredentials() error {
	tcm.accountID = ""
	tcm.accessKey = ""
	return nil
}

func (tcm *TenantConfigMock) GetAccessKey() string {
	return tcm.accessKey
}

func TestDisplayMessage(t *testing.T) {

	t.Run("should display an empty message", func(t *testing.T) {

		reporter := NewReportEventReceiver(
			&TenantConfigMock{
				clusterName: "test",
				accountID:   "1234",
			},
			"",
			SubmitContextScan,
			getter.GetKSCloudAPIConnector(),
		)

		capture, clean := captureStdout(t)
		defer clean()

		reporter.DisplayMessage()
		require.NoError(t, capture.Close())

		buf, err := os.ReadFile(capture.Name())
		require.NoError(t, err)

		require.Empty(t, buf)
	})

	t.Run("should display a non-empty message", func(t *testing.T) {

		reporter := NewReportEventReceiver(
			&TenantConfigMock{
				clusterName: "test",
				accountID:   "1234",
			},
			"",
			SubmitContextScan,
			getter.GetKSCloudAPIConnector(),
		)
		reporter.setMessage("message returned from server")

		capture, clean := captureStdout(t)
		defer clean()

		reporter.DisplayMessage()
		require.NoError(t, capture.Close())

		buf, err := os.ReadFile(capture.Name())
		require.NoError(t, err)

		require.NotEmpty(t, buf)
		assert.Contains(t, string(buf), "message returned from server")

		t.Log(string(buf))
	})
}

func TestPrepareReport(t *testing.T) {

	t.Run("should keep the original scanning target it received and not mutate it", func(t *testing.T) {
		testCases := []struct {
			Name string
			Want reporthandlingv2.ScanningTarget
		}{
			{"Cluster", reporthandlingv2.Cluster},
			{"File", reporthandlingv2.File},
			{"Repo", reporthandlingv2.Repo},
			{"GitLocal", reporthandlingv2.GitLocal},
			{"Directory", reporthandlingv2.Directory},
		}

		reporter := NewReportEventReceiver(
			&TenantConfigMock{
				clusterName: "test",
				accountID:   "1e3ae7c4-a8bb-4d7c-9bdf-eb86bc25e6bb",
			},
			"",
			SubmitContextScan,
			getter.GetKSCloudAPIConnector(),
		)

		for _, tc := range testCases {
			t.Run(tc.Name, func(t *testing.T) {
				want := tc.Want

				opaSessionObj := &cautils.OPASessionObj{
					Report: &reporthandlingv2.PostureReport{},
					Metadata: &reporthandlingv2.Metadata{
						ScanMetadata: reporthandlingv2.ScanMetadata{ScanningTarget: want},
					},
				}

				reporter.prepareReport(opaSessionObj)

				got := opaSessionObj.Metadata.ScanMetadata.ScanningTarget
				require.Equalf(t, want, got,
					"Scanning targets don’t match after preparing report. Got: %v, want %v", got, want,
				)
			})
		}
	})
}

func TestSubmit(t *testing.T) {
	ctx := context.Background()
	srv := mockAPIServer(t)
	t.Cleanup(srv.Close)

	const account = "1e3ae7c4-a8bb-4d7c-9bdf-eb86bc25e6bb"
	const accessKey = "ef871116-b4c9-4dbc-9abb-f422f025429f"

	t.Run("should submit simple report", func(t *testing.T) {
		ksCloud, err := v1.NewKSCloudAPI(
			srv.Root(),
			srv.Root(),
			account,
			accessKey,
			v1.WithHTTPClient(hijackedClient(t, srv))) // re-route the http client to our mock server, as this is not easily configurable in the reporter.
		require.NoError(t, err)

		reporter := NewReportEventReceiver(
			&TenantConfigMock{
				clusterName: "test",
				accountID:   account,
				accessKey:   accessKey,
			},
			"cbabd56f-bac6-416a-836b-b815ef347647",
			SubmitContextScan,
			ksCloud,
		)

		opaSession := mockOPASessionObj(t)
		require.NoError(t,
			reporter.Submit(ctx, opaSession),
		)
	})

	t.Run("should delete credentials only on first chunk failure", func(t *testing.T) {
		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "mock server error", http.StatusInternalServerError)
		}))
		defer mockServer.Close()

		// Test 1: First chunk fails (counter == 0)
		tenantMock1 := &TenantConfigMock{
			clusterName: "test",
			accountID:   account,
		}

		ksCloud1, err := v1.NewKSCloudAPI(
			mockServer.URL,
			mockServer.URL,
			account,
			accessKey)
		require.NoError(t, err)

		reporter1 := NewReportEventReceiver(
			tenantMock1,
			"cbabd56f-bac6-416a-836b-b815ef347647",
			SubmitContextScan,
			ksCloud1,
		)
		reporter1.accountIdGenerated = true // Simulate account generation

		// Fail on chunk 0
		err = reporter1.sendReport(&reporthandlingv2.PostureReport{}, 0, false)
		require.Error(t, err) // Mock will fail since it's empty / unsupported format in this test setup
		assert.Equal(t, 0, len(tenantMock1.GetAccountID()), "Account ID should be deleted on first chunk failure")

		// Test 2: Second chunk fails (counter == 1)
		tenantMock2 := &TenantConfigMock{
			clusterName: "test",
			accountID:   account,
		}

		ksCloud2, err := v1.NewKSCloudAPI(
			mockServer.URL,
			mockServer.URL,
			account,
			accessKey)
		require.NoError(t, err)

		reporter2 := NewReportEventReceiver(
			tenantMock2,
			"cbabd56f-bac6-416a-836b-b815ef347647",
			SubmitContextScan,
			ksCloud2,
		)
		reporter2.accountIdGenerated = true

		err = reporter2.sendReport(&reporthandlingv2.PostureReport{}, 1, false)
		require.Error(t, err)
		assert.Equal(t, account, tenantMock2.GetAccountID(), "Account ID should NOT be deleted on subsequent chunk failures")
	})

	t.Run("should generate new account if account is empty", func(t *testing.T) {
		ksCloud, err := v1.NewKSCloudAPI(
			srv.Root(),
			srv.Root(),
			"",
			"",
			v1.WithHTTPClient(hijackedClient(t, srv))) // re-route the http client to our mock server, as this is not easily configurable in the reporter.
		require.NoError(t, err)

		reporter := NewReportEventReceiver(
			&TenantConfigMock{
				clusterName: "test",
				accountID:   "",
			},
			"cbabd56f-bac6-416a-836b-b815ef347647",
			SubmitContextScan,
			ksCloud,
		)

		opaSession := mockOPASessionObj(t)

		capture, clean := captureStdout(t)
		if pretty, ok := logger.L().(*prettylogger.PrettyLogger); ok {
			pretty.SetWriter(capture)
		}

		defer func() {
			clean()
			if pretty, ok := logger.L().(*prettylogger.PrettyLogger); ok {
				pretty.SetWriter(os.Stderr)
			}
		}()

		require.NoError(t,
			reporter.Submit(ctx, opaSession),
		)

		assert.Equalf(t, testGeneratedAccountIDString, reporter.GetAccountID(), "reporter should have generated a new account ID")
	})

	t.Run("should warn when no cluster name", func(t *testing.T) {
		ksCloud, err := v1.NewKSCloudAPI(
			srv.Root(),
			srv.Root(),
			account,
			accessKey,
			v1.WithHTTPClient(hijackedClient(t, srv))) // re-route the http client to our mock server, as this is not easily configurable in the reporter.
		require.NoError(t, err)

		reporter := NewReportEventReceiver(
			&TenantConfigMock{
				clusterName: "",
				accountID:   account,
				accessKey:   accessKey,
			},
			"cbabd56f-bac6-416a-836b-b815ef347647",
			SubmitContextScan,
			ksCloud,
		)

		opaSession := mockOPASessionObj(t)
		opaSession.Metadata.ScanMetadata.ScanningTarget = reporthandlingv2.Cluster

		capture, clean := captureStdout(t)
		if pretty, ok := logger.L().(*prettylogger.PrettyLogger); ok {
			pretty.SetWriter(capture)
		}

		defer func() {
			clean()
			if pretty, ok := logger.L().(*prettylogger.PrettyLogger); ok {
				pretty.SetWriter(os.Stderr)
			}
		}()

		require.NoError(t,
			reporter.Submit(ctx, opaSession),
		)
		require.NoError(t, capture.Close())

		buf, err := os.ReadFile(capture.Name())
		require.NoError(t, err)

		assert.Contains(t, string(buf), "failed to publish result")
		assert.Contains(t, string(buf), "cluster name")
	})
}

func TestSetters(t *testing.T) {

	pickString := func() string {
		return strconv.Itoa(rand.Intn(10000)) //nolint:gosec
	}

	reporter := NewReportEventReceiver(
		&TenantConfigMock{
			clusterName: "",
			accountID:   "1e3ae7c4-a8bb-4d7c-9bdf-eb86bc25e6bb",
		},
		"cbabd56f-bac6-416a-836b-b815ef347647",
		SubmitContextScan,
		getter.GetKSCloudAPIConnector(),
	)

	t.Run("should set tenantConfig", func(t *testing.T) {
		clusterName := pickString()
		accountID := pickString()
		reporter.SetTenantConfig(&TenantConfigMock{
			clusterName: clusterName,
			accountID:   accountID,
		})

		require.Equal(t, accountID, reporter.GetAccountID())
		require.Equal(t, clusterName, reporter.GetClusterName())
	})

	t.Run("should normalize cluster name", func(t *testing.T) {
		const cluster = " x   y\t\tz"
		reporter.SetTenantConfig(&TenantConfigMock{clusterName: cluster, accountID: ""})

		require.Equal(t, "-x-y-z", reporter.GetClusterName())
	})
}

func captureStderr(t testing.TB) (*os.File, func()) {
	mxStdio.Lock()
	saved := os.Stderr
	capture, err := os.CreateTemp("", "stderr")
	if !assert.NoError(t, err) {
		mxStdio.Unlock()

		t.FailNow()

		return nil, nil
	}
	os.Stderr = capture

	return capture, func() {
		_ = capture.Close()
		_ = os.Remove(capture.Name())

		os.Stderr = saved
		mxStdio.Unlock()
	}
}

func captureStdout(t testing.TB) (*os.File, func()) {
	mxStdio.Lock()
	saved := os.Stdout
	capture, err := os.CreateTemp("", "stdout")
	if !assert.NoError(t, err) {
		mxStdio.Unlock()

		t.FailNow()

		return nil, nil
	}
	os.Stdout = capture

	return capture, func() {
		_ = capture.Close()
		_ = os.Remove(capture.Name())

		os.Stdout = saved
		mxStdio.Unlock()
	}
}
