package reporter

import (
	"context"
	"math/rand"
	"net/url"
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

func TestReportEventReceiver_addPathURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		report *ReportEventReceiver
		urlObj *url.URL
		want   *url.URL
		name   string
	}{
		{
			name: "URL for submitted data",
			report: &ReportEventReceiver{
				clusterName:        "test",
				customerGUID:       "FFFF",
				token:              "XXXX",
				customerAdminEMail: "test@test",
				reportID:           "1234",
				submitContext:      SubmitContextScan,
			},
			urlObj: &url.URL{
				Scheme: "https",
				Host:   "localhost:8080",
			},
			want: &url.URL{
				Scheme:   "https",
				Host:     "localhost:8080",
				Path:     "compliance/test",
				RawQuery: "",
			},
		},
		{
			name: "URL for first scan",
			report: &ReportEventReceiver{
				clusterName:   "test",
				customerGUID:  "FFFF",
				token:         "XXXX",
				reportID:      "1234",
				submitContext: SubmitContextScan,
			},
			urlObj: &url.URL{
				Scheme: "https",
				Host:   "localhost:8080",
			},
			want: &url.URL{
				Scheme:   "https",
				Host:     "localhost:8080",
				Path:     "account/sign-up",
				RawQuery: "customerGUID=FFFF&invitationToken=XXXX&utm_medium=createaccount&utm_source=ARMOgithub",
			},
		},
		{
			name: "add rbac path",
			report: &ReportEventReceiver{
				clusterName:        "test",
				customerGUID:       "FFFF",
				token:              "XXXX",
				customerAdminEMail: "test@test",
				reportID:           "1234",
				submitContext:      SubmitContextRBAC,
			},
			urlObj: &url.URL{
				Scheme: "https",
				Host:   "localhost:8080",
			},
			want: &url.URL{
				Scheme: "https",
				Host:   "localhost:8080",
				Path:   "rbac-visualizer",
			},
		},
		{
			name: "add repository path",
			report: &ReportEventReceiver{
				clusterName:        "test",
				customerGUID:       "FFFF",
				token:              "XXXX",
				customerAdminEMail: "test@test",
				reportID:           "1234",
				submitContext:      SubmitContextRepository,
			},
			urlObj: &url.URL{
				Scheme: "https",
				Host:   "localhost:8080",
			},
			want: &url.URL{
				Scheme: "https",
				Host:   "localhost:8080",
				Path:   "repository-scanning/1234",
			},
		},
		{
			name: "add default path",
			report: &ReportEventReceiver{
				clusterName:        "test",
				customerGUID:       "FFFF",
				token:              "XXXX",
				customerAdminEMail: "test@test",
				reportID:           "1234",
				submitContext:      SubmitContext("invalid"),
			},
			urlObj: &url.URL{
				Scheme: "https",
				Host:   "localhost:8080",
			},
			want: &url.URL{
				Scheme: "https",
				Host:   "localhost:8080",
				Path:   "dashboard",
			},
		},
		{
			name: "path when no email and no token",
			report: &ReportEventReceiver{
				clusterName:        "test",
				customerGUID:       "FFFF",
				token:              "",
				customerAdminEMail: "",
				reportID:           "1234",
				submitContext:      SubmitContextScan,
			},
			urlObj: &url.URL{
				Scheme: "https",
				Host:   "localhost:8080",
			},
			want: &url.URL{
				Scheme: "https",
				Host:   "localhost:8080",
				Path:   "compliance/test",
			},
		},
		{
			name: "path when email and no token",
			report: &ReportEventReceiver{
				clusterName:        "test",
				customerGUID:       "FFFF",
				token:              "",
				customerAdminEMail: "test@test",
				reportID:           "1234",
				submitContext:      SubmitContextScan,
			},
			urlObj: &url.URL{
				Scheme: "https",
				Host:   "localhost:8080",
			},
			want: &url.URL{
				Scheme: "https",
				Host:   "localhost:8080",
				Path:   "compliance/test",
			},
		},
		{
			name: "path when no email and token",
			report: &ReportEventReceiver{
				clusterName:        "test",
				customerGUID:       "FFFF",
				token:              "XYZ",
				customerAdminEMail: "",
				reportID:           "1234",
				submitContext:      SubmitContextScan,
			},
			urlObj: &url.URL{
				Scheme: "https",
				Host:   "localhost:8080",
			},
			want: &url.URL{
				Scheme:   "https",
				Host:     "localhost:8080",
				Path:     "account/sign-up",
				RawQuery: "customerGUID=FFFF&invitationToken=XYZ&utm_medium=createaccount&utm_source=ARMOgithub",
			},
		},
	}
	for _, toPin := range tests {
		tc := toPin

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.report.addPathURL(tc.urlObj)
			require.Equal(t, tc.want.String(), tc.urlObj.String())
		})
	}
}

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
		reporter.generateMessage()

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
			&cautils.ConfigObj{
				AccountID:   "1e3ae7c4-a8bb-4d7c-9bdf-eb86bc25e6bb",
				Token:       "",
				ClusterName: "test",
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

	t.Run("should warn when no customerGUID", func(t *testing.T) {
		reporter := NewReportEventReceiver(
			&cautils.ConfigObj{
				Token:       "",
				ClusterName: "test",
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
		require.NoError(t, capture.Close())

		buf, err := os.ReadFile(capture.Name())
		require.NoError(t, err)

		assert.Contains(t, string(buf), "failed to publish result")
		assert.Contains(t, string(buf), "Unknown acc")
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

		require.Equal(t, guid, reporter.customerGUID)
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
