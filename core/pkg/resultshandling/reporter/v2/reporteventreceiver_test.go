package reporter

import (
	"net/url"
	"testing"

	"github.com/kubescape/kubescape/v2/core/cautils"
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
				Path:   "configuration-scanning/test",
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
		assert.Equal(t, "https://cloud.armosec.io/configuration-scanning/test?utm_campaign=Submit&utm_medium=CLI&utm_source=GitHub", reporter.GetURL())
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
		assert.Equal(t, "https://cloud.armosec.io/rbac-visualizer?utm_campaign=Submit&utm_medium=CLI&utm_source=GitHub", reporter.GetURL())
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
		assert.Equal(t, "https://cloud.armosec.io/repository-scanning/XXXX?utm_campaign=Submit&utm_medium=CLI&utm_source=GitHub", reporter.GetURL())
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
		assert.Equal(t, "https://cloud.armosec.io/account/sign-up?customerGUID=1234&invitationToken=token&utm_campaign=Submit&utm_medium=CLI&utm_source=GitHub", reporter.GetURL())
	}
}
