package v2

import (
	_ "embed"
	"encoding/json"
	"net/url"
	"testing"

	"github.com/kubescape/kubescape/v2/core/cautils"
	"github.com/kubescape/opa-utils/reporthandling"
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
		assert.Equal(t, "https://cloud.armosec.io/repositories-scan/XXXX?utm_campaign=Submit&utm_medium=CLI&utm_source=GitHub", reporter.GetURL())
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
	// Test None submit url
	{
		reporter := NewReportMock(NO_SUBMIT_QUERY, "")
		assert.Equal(t, "https://cloud.armosec.io/account/sign-up?utm_source=GitHub&utm_medium=CLI&utm_campaign=no_submit", reporter.GetURL())
	}
	// Test None report url
	{
		reporter := NewReportMock("", "")
		assert.Equal(t, "https://cloud.armosec.io/account/sign-up", reporter.GetURL())
	}
}


var (
	//go:embed testdata/ks-deployment.json
	 deployment_with_containers string
	 //go: embed testdata/ks-deployment-without-container.json
	 deployment_without_containers string
)

func TestRawResourceContainerHandler(t *testing.T) {
	tests := []struct {
		name    string
		resorce string
		want    []reporthandling.Resource
	}{
		{
			name:    "without containers",
			resorce: deployment_without_containers,
			want:    []reporthandling.Resource{},
		},
		{
			name:    "one container",
			resorce: deployment_with_containers,
			want: []reporthandling.Resource{{
				ResourceID: "14999009265974204971",
				Object: Container{
					Kind:       "Container",
					ApiVersion: "container.kubscape.cloud",
					ImageTag:   "quay.io/armosec/demoservice:v25",
					Metadata: ContainerMetadata{
						Metadata: &Metadata{Name: "quay.io/armosec/demoservice:v25"},
						Parent: Metadata{
							Namespace:  "default",
							Name:       "demoservice-server",
							Kind:       "Deployment",
							ApiVersion: "apps/v1",
						},
					},
				}}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			object := make(map[string]interface{})
			json.Unmarshal([]byte(tt.resorce), &object)
			parentResorce := reporthandling.Resource{Object: object}
			assert.Equal(t, tt.want, rawResourceContainerHandler(parentResorce))
		})
	}
}
