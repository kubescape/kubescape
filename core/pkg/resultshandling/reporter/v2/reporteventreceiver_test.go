package reporter

import (
	"context"
	"math/rand"
	"os"
	"strconv"
	"sync"
	"testing"

	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/prettylogger"
	"github.com/kubescape/kubescape/v2/core/cautils"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mxStdio serializes the capture of os.Stderr or os.Stdout
var mxStdio sync.Mutex

type TenantConfigMock struct {
	clusterName string
	accountID   string
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

func (tcm *TenantConfigMock) DeleteAccountID() error {
	tcm.accountID = ""
	return nil
}

func TestDisplayMessage(t *testing.T) {
	t.Parallel()

	t.Run("should display an empty message", func(t *testing.T) {
		t.Parallel()

		reporter := NewReportEventReceiver(
			&TenantConfigMock{
				clusterName: "test",
				accountID:   "1234",
			},
			"",
			SubmitContextScan,
		)

		capture, clean := captureStderr(t)
		defer clean()

		reporter.DisplayMessage()
		require.NoError(t, capture.Close())

		buf, err := os.ReadFile(capture.Name())
		require.NoError(t, err)

		require.Empty(t, buf)
	})

	t.Run("should display a non-empty message", func(t *testing.T) {
		t.Parallel()

		reporter := NewReportEventReceiver(
			&TenantConfigMock{
				clusterName: "test",
				accountID:   "1234",
			},
			"",
			SubmitContextScan,
		)
		reporter.setMessage("message returned from server")

		capture, clean := captureStderr(t)
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
	t.Parallel()

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

	t.Run("should submit simple report", func(t *testing.T) {
		reporter := NewReportEventReceiver(
			&TenantConfigMock{
				clusterName: "test",
				accountID:   "1e3ae7c4-a8bb-4d7c-9bdf-eb86bc25e6bb",
			},
			"cbabd56f-bac6-416a-836b-b815ef347647",
			SubmitContextScan,
		)

		opaSession := mockOPASessionObj(t)
		reporter.httpClient = hijackedClient(t, srv) // re-route the http client to our mock server, as this is not easily configurable in the reporter.

		require.NoError(t,
			reporter.Submit(ctx, opaSession),
		)
	})

	t.Run("should generate new customerGUID when no customerGUID", func(t *testing.T) {
		reporter := NewReportEventReceiver(
			&TenantConfigMock{
				clusterName: "test",
				accountID:   "",
			},
			"cbabd56f-bac6-416a-836b-b815ef347647",
			SubmitContextScan,
		)

		opaSession := mockOPASessionObj(t)
		reporter.httpClient = hijackedClient(t, srv)

		capture, clean := captureStderr(t)
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
		reporter := NewReportEventReceiver(
			&TenantConfigMock{
				clusterName: "",
				accountID:   "1e3ae7c4-a8bb-4d7c-9bdf-eb86bc25e6bb",
			},
			"cbabd56f-bac6-416a-836b-b815ef347647",
			SubmitContextScan,
		)

		opaSession := mockOPASessionObj(t)
		opaSession.Metadata.ScanMetadata.ScanningTarget = reporthandlingv2.Cluster

		reporter.httpClient = hijackedClient(t, srv)

		capture, clean := captureStderr(t)
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
	t.Parallel()

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
