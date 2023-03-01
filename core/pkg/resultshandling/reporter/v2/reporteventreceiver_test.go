package reporter

import (
	"net/url"
	"testing"

	"github.com/kubescape/kubescape/v2/core/cautils"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/stretchr/testify/assert"
)

func TestReportEventReceiver_addPathURL(t *testing.T) {
	tests := []struct {
		name   string
		report *ReportEventReceiver
		urlObj *url.URL
		want   *url.URL
	}{
		{
			name: "add scan path",
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
				Scheme: "https",
				Host:   "localhost:8080",
				Path:   "compliance/test",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.report.addPathURL(tt.urlObj)
			assert.Equal(t, tt.want.String(), tt.urlObj.String())

		})
	}
}

func TestGetURL(t *testing.T) {
	// Test submit and registered url
	{
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
		assert.Equal(t, "https://cloud.armosec.io/compliance/test?utm_medium=ARMOcli&utm_source=ARMOgithub", reporter.GetURL())
	}

	// Test rbac submit and registered url
	{
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
		assert.Equal(t, "https://cloud.armosec.io/rbac-visualizer?utm_medium=ARMOcli&utm_source=ARMOgithub", reporter.GetURL())
	}

	// Test repo submit and registered url
	{
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
		assert.Equal(t, "https://cloud.armosec.io/repository-scanning/XXXX?utm_medium=ARMOcli&utm_source=ARMOgithub", reporter.GetURL())
	}

	// Test submit and NOT registered url
	{

		reporter := NewReportEventReceiver(
			&cautils.ConfigObj{
				AccountID:   "1234",
				Token:       "token",
				ClusterName: "test",
			},
			"",
			SubmitContextScan,
		)
		assert.Equal(t, "https://cloud.armosec.io/account/sign-up?customerGUID=1234&invitationToken=token&utm_medium=ARMOcli&utm_source=ARMOgithub", reporter.GetURL())
	}
}

func Test_prepareReportKeepsOriginalScanningTarget(t *testing.T) {

	// prepareReport should keep the original scanning target it received, and not mutate it
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
			if got != want {
				t.Errorf("Scanning targets don’t match after preparing report. Got: %v, want %v", got, want)
			}
		},
		)
	}
}
