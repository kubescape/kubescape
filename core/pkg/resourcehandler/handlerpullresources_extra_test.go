package resourcehandler

import (
	"context"
	"errors"
	"testing"

	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v3/core/cautils"
	reportv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/version"
)

type collectResourcesMock struct {
	k8sResources      cautils.K8SResources
	allResources      map[string]workloadinterface.IMetadata
	externalResources cautils.ExternalResources
	excludedRules     map[string]bool
	err               error
	cloudProvider     string
	apiServerInfo     *version.Info
}

func (m collectResourcesMock) GetResources(context.Context, *cautils.OPASessionObj, *cautils.ScanInfo) (cautils.K8SResources, map[string]workloadinterface.IMetadata, cautils.ExternalResources, map[string]bool, error) {
	return m.k8sResources, m.allResources, m.externalResources, m.excludedRules, m.err
}

func (m collectResourcesMock) GetClusterAPIServerInfo(context.Context) *version.Info {
	return m.apiServerInfo
}

func (m collectResourcesMock) GetCloudProvider() string {
	return m.cloudProvider
}

func TestCollectResources(t *testing.T) {
	tests := []struct {
		name       string
		handler    collectResourcesMock
		wantErr    string
		assertions func(t *testing.T, session *cautils.OPASessionObj)
	}{
		{
			name: "assigns returned resource maps",
			handler: collectResourcesMock{
				k8sResources:  cautils.K8SResources{"apps/v1/deployments": []string{"resource-1"}},
				allResources:  map[string]workloadinterface.IMetadata{"resource-1": nil},
				excludedRules: map[string]bool{"rule-1": true},
				apiServerInfo: &version.Info{GitVersion: "v1.30.0"},
			},
			assertions: func(t *testing.T, session *cautils.OPASessionObj) {
				assert.Equal(t, []string{"resource-1"}, session.K8SResources["apps/v1/deployments"])
				assert.Contains(t, session.AllResources, "resource-1")
				assert.True(t, session.ExcludedRules["rule-1"])
				assert.Equal(t, "v1.30.0", session.Report.ClusterAPIServerInfo.GitVersion)
			},
		},
		{
			name: "returns get resources error after assigning maps",
			handler: collectResourcesMock{
				k8sResources: cautils.K8SResources{"v1/pods": []string{"pod-1"}},
				allResources: map[string]workloadinterface.IMetadata{"pod-1": nil},
				err:          errors.New("pull failed"),
			},
			wantErr: "pull failed",
			assertions: func(t *testing.T, session *cautils.OPASessionObj) {
				assert.Equal(t, []string{"pod-1"}, session.K8SResources["v1/pods"])
				assert.Contains(t, session.AllResources, "pod-1")
			},
		},
		{
			name: "returns no resources error for empty results",
			handler: collectResourcesMock{
				k8sResources: cautils.K8SResources{},
				allResources: map[string]workloadinterface.IMetadata{},
			},
			wantErr: "no resources found to scan",
		},
		{
			name: "ignores unknown cloud provider",
			handler: collectResourcesMock{
				k8sResources:  cautils.K8SResources{"v1/configmaps": []string{"cm-1"}},
				allResources:  map[string]workloadinterface.IMetadata{"cm-1": nil},
				cloudProvider: "unknown",
			},
			assertions: func(t *testing.T, session *cautils.OPASessionObj) {
				assert.Empty(t, session.Report.ClusterCloudProvider)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := &cautils.OPASessionObj{
				Metadata: &reportv2.Metadata{},
				Report:   &reportv2.PostureReport{},
			}

			err := CollectResources(context.Background(), tt.handler, session, &cautils.ScanInfo{})
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
			} else {
				require.NoError(t, err)
			}
			if tt.assertions != nil {
				tt.assertions(t, session)
			}
		})
	}
}
