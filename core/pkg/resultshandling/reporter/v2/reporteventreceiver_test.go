package reporter

import (
	"context"
	"errors"
	"math/rand"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/prettylogger"
	"github.com/kubescape/kubescape/v2/core/cautils"
	"github.com/kubescape/kubescape/v2/core/cautils/getter"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mxStdio serializes the capture of os.Stderr or os.Stdout
var mxStdio sync.Mutex

func TestGetURL(t *testing.T) {
	t.Parallel()

	t.Run("with scan submit and registered url", func(t *testing.T) {
		t.Parallel()

		reporter := NewReportEventReceiver(
			&cautils.ConfigObj{
				AccountID:          "1234",
				Token:              "token",
				CustomerAdminEMail: "my@email",
				ClusterName:        "test",
			},
			"",
			SubmitContextScan,
		)
		assert.Equal(t, "https://cloud.armosec.io/compliance/test", reporter.GetURL())
	})

	t.Run("with rbac submit and registered url", func(t *testing.T) {
		t.Parallel()

		reporter := NewReportEventReceiver(
			&cautils.ConfigObj{
				AccountID:          "1234",
				Token:              "token",
				CustomerAdminEMail: "my@email",
				ClusterName:        "test",
			},
			"",
			SubmitContextRBAC,
		)
		assert.Equal(t, "https://cloud.armosec.io/rbac-visualizer", reporter.GetURL())
	})

	t.Run("with repository submit and registered url", func(t *testing.T) {
		t.Parallel()

		reporter := NewReportEventReceiver(
			&cautils.ConfigObj{
				AccountID:          "1234",
				Token:              "token",
				CustomerAdminEMail: "my@email",
				ClusterName:        "test",
			},
			"XXXX",
			SubmitContextRepository,
		)
		assert.Equal(t, "https://cloud.armosec.io/repository-scanning/XXXX", reporter.GetURL())
	})

	t.Run("with scan submit and NOT registered url", func(t *testing.T) {
		t.Parallel()

		reporter := NewReportEventReceiver(
			&cautils.ConfigObj{
				AccountID:   "1234",
				Token:       "token",
				ClusterName: "test",
			},
			"",
			SubmitContextScan,
		)
		assert.Equal(t, "https://cloud.armosec.io/account/sign-up?customerGUID=1234&invitationToken=token&utm_medium=createaccount&utm_source=ARMOgithub", reporter.GetURL())
	})

	t.Run("with unknown submit and NOT registered url (default route)", func(t *testing.T) {
		t.Parallel()

		reporter := NewReportEventReceiver(
			&cautils.ConfigObj{
				AccountID:   "1234",
				ClusterName: "test",
			},
			"",
			SubmitContext("unknown"),
		)
		assert.Equal(t, "https://cloud.armosec.io/dashboard", reporter.GetURL())
	})
}

func TestDisplayReportURL(t *testing.T) {
	t.Parallel()

	t.Run("should display an empty message", func(t *testing.T) {
		t.Parallel()

		reporter := NewReportEventReceiver(
			&cautils.ConfigObj{
				AccountID:   "1234",
				Token:       "token",
				ClusterName: "test",
			},
			"",
			SubmitContextScan,
		)

		capture, clean := captureStderr(t)
		defer clean()

		reporter.DisplayReportURL()
		require.NoError(t, capture.Close())

		buf, err := os.ReadFile(capture.Name())
		require.NoError(t, err)

		require.Empty(t, buf)
	})

	t.Run("should display a non-empty message", func(t *testing.T) {
		t.Parallel()

		reporter := NewReportEventReceiver(
			&cautils.ConfigObj{
				AccountID:   "1234",
				Token:       "token",
				ClusterName: "test",
			},
			"",
			SubmitContextScan,
		)

		reporter.posted = true

		capture, clean := captureStderr(t)
		defer clean()

		reporter.DisplayReportURL()
		require.NoError(t, capture.Close())

		buf, err := os.ReadFile(capture.Name())
		require.NoError(t, err)

		require.NotEmpty(t, buf)
		assert.Contains(t, string(buf), "WOW!")
		assert.Contains(t, string(buf), "https://cloud.armosec.io/account/sign-up")

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
			&cautils.ConfigObj{
				AccountID:   "1e3ae7c4-a8bb-4d7c-9bdf-eb86bc25e6bb",
				Token:       "token",
				ClusterName: "test",
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

				reporter.sendChunkedReport(opaSessionObj)

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
			&cautils.ConfigObj{
				AccountID:   "1e3ae7c4-a8bb-4d7c-9bdf-eb86bc25e6bb",
				Token:       "",
				ClusterName: "test",
			},
			"cbabd56f-bac6-416a-836b-b815ef347647",
			SubmitContextScan,
		)

		setTestKSCloudClient(reporter, srv)
		opaSession := mockOPASessionObj(t)

		require.NoError(t,
			reporter.Submit(ctx, opaSession),
		)
	})

	t.Run("should warn when no customerGUID", func(t *testing.T) {
		reporter := NewReportEventReceiver(
			&cautils.ConfigObj{
				Token:       "",
				ClusterName: "test",
			},
			"cbabd56f-bac6-416a-836b-b815ef347647",
			SubmitContextScan,
		)

		setTestKSCloudClient(reporter, srv)
		opaSession := mockOPASessionObj(t)

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
		assert.Contains(t, string(buf), "Unknown acc")

		require.False(t, reporter.posted)
	})

	t.Run("should warn when no cluster name", func(t *testing.T) {
		reporter := NewReportEventReceiver(
			&cautils.ConfigObj{
				AccountID: "1e3ae7c4-a8bb-4d7c-9bdf-eb86bc25e6bb",
				Token:     "",
			},
			"cbabd56f-bac6-416a-836b-b815ef347647",
			SubmitContextScan,
		)

		setTestKSCloudClient(reporter, srv)
		opaSession := mockOPASessionObj(t)
		opaSession.Metadata.ScanMetadata.ScanningTarget = reporthandlingv2.Cluster

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

		require.False(t, reporter.posted)
	})

	t.Run("should submit paginated report", func(t *testing.T) {
		reporter := NewReportEventReceiver(
			&cautils.ConfigObj{
				AccountID:   "1e3ae7c4-a8bb-4d7c-9bdf-eb86bc25e6bb",
				Token:       "",
				ClusterName: "test",
			},
			"cbabd56f-bac6-416a-836b-b815ef347647",
			SubmitContextScan,
		)
		reporter.maxReportSize = 2 * 1024
		setTestKSCloudClient(reporter, srv)
		opaSession := mockOPASessionObj(t, withGrowMock(200))

		require.NoError(t,
			reporter.Submit(ctx, opaSession),
		)
		const expectedMinPostedPages = 2
		require.Greater(t, reporter.postedCount, expectedMinPostedPages)
	})
}

func TestSubmitWithAuth(t *testing.T) {
	ctx := context.Background()
	srv := mockAPIServer(t, withAPIAuth(true)) // mock server will assert that an Authorization header is hydrated
	t.Cleanup(srv.Close)

	t.Run("should submit simple report with the tenant's auth token", func(t *testing.T) {
		reporter := NewReportEventReceiver(
			&cautils.ConfigObj{
				AccountID:   "1e3ae7c4-a8bb-4d7c-9bdf-eb86bc25e6bb",
				Token:       "",
				ClusterName: "test",
			},
			"cbabd56f-bac6-416a-836b-b815ef347647",
			SubmitContextScan,
		)
		reporter.SetInvitationToken("auth-token")
		setTestKSCloudClient(reporter, srv)
		opaSession := mockOPASessionObj(t)

		require.NoError(t,
			reporter.Submit(ctx, opaSession),
		)
	})
}

func TestSubmitWithError(t *testing.T) {
	ctx := context.Background()
	apiErr := errors.New("test error")
	srv := mockAPIServer(t, withAPIError(apiErr)) // mock server will error on every call
	t.Cleanup(srv.Close)

	t.Run("should error on submit simple report", func(t *testing.T) {
		reporter := NewReportEventReceiver(
			&cautils.ConfigObj{
				AccountID:   "1e3ae7c4-a8bb-4d7c-9bdf-eb86bc25e6bb",
				Token:       "",
				ClusterName: "test",
			},
			"cbabd56f-bac6-416a-836b-b815ef347647",
			SubmitContextScan,
		)
		reporter.SetInvitationToken("auth-token")
		setTestKSCloudClient(reporter, srv)
		opaSession := mockOPASessionObj(t)

		err := reporter.Submit(ctx, opaSession)
		require.Error(t, err)

		assert.Contains(t, err.Error(), "500 Internal Server Error")
		assert.Contains(t, err.Error(), apiErr.Error())
	})
}

func TestSetters(t *testing.T) {
	t.Parallel()

	pickString := func() string {
		return strconv.Itoa(rand.Intn(10000)) //nolint:gosec
	}

	reporter := NewReportEventReceiver(
		&cautils.ConfigObj{
			AccountID: "1e3ae7c4-a8bb-4d7c-9bdf-eb86bc25e6bb",
			Token:     "",
		},
		"cbabd56f-bac6-416a-836b-b815ef347647",
		SubmitContextScan,
	)

	t.Run("should set customerID", func(t *testing.T) {
		guid := pickString()
		reporter.SetCustomerGUID(guid)

		require.Equal(t, guid, reporter.GetAccountID())
	})

	t.Run("should set cluster name", func(t *testing.T) {
		cluster := pickString()
		reporter.SetClusterName(cluster)

		require.Equal(t, cluster, reporter.clusterName)
	})

	t.Run("should normalize cluster name", func(t *testing.T) {
		const cluster = " x   y\t\tz"
		reporter.SetClusterName(cluster)

		require.Equal(t, "-x-y-z", reporter.clusterName)
	})
}

// setTestKSCloudClient overrides the inner KSCloudAPI client to point to a mock HTTP server.
func setTestKSCloudClient(reporter *ReportEventReceiver, srv *testServer) {
	guid := reporter.GetAccountID()
	invitationToken := reporter.GetInvitationToken()

	reporter.KSCloudAPI = getter.NewKSCloudAPICustomized(srv.Root(), srv.Root(),
		getter.WithHTTPClient(srv.Client()),
		getter.WithTimeout(500*time.Millisecond),
		getter.WithTrace(os.Getenv("DEBUG_TEST") != ""),
		getter.WithReportURL(srv.Root()),
		getter.WithFrontendURL(srv.Root()),
	)
	reporter.SetAccountID(guid)
	reporter.SetInvitationToken(invitationToken)
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
