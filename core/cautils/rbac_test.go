package cautils

import (
	"testing"

	"github.com/kubescape/rbac-utils/rbacscanner"
	"github.com/stretchr/testify/assert"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestRBACObjectsSetResourcesReport(t *testing.T) {
	tests := []struct {
		name         string
		customerGUID string
		clusterName  string
	}{
		{
			name:         "cluster with customer guid",
			customerGUID: "customer-1",
			clusterName:  "prod-cluster",
		},
		{
			name:        "cluster without customer guid",
			clusterName: "dev-cluster",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rbacObjects := NewRBACObjects(&rbacscanner.RbacScannerFromK8sAPI{
				CustomerGUID: tt.customerGUID,
				ClusterName:  tt.clusterName,
			})

			report, err := rbacObjects.SetResourcesReport()

			assert.NoError(t, err)
			assert.NotEmpty(t, report.ReportID)
			assert.False(t, report.ReportGenerationTime.IsZero())
			assert.Equal(t, tt.customerGUID, report.CustomerGUID)
			assert.Equal(t, tt.clusterName, report.ClusterName)
			assert.NotNil(t, report.Metadata.ContextMetadata.ClusterContextMetadata)
			assert.Equal(t, tt.clusterName, report.Metadata.ContextMetadata.ClusterContextMetadata.ContextName)
		})
	}
}

func TestConvertToMap(t *testing.T) {
	tests := []struct {
		name          string
		obj           interface{}
		expectedName  string
		expectedError string
	}{
		{
			name: "role",
			obj: rbacv1.Role{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "reader",
					Namespace: "default",
				},
				Rules: []rbacv1.PolicyRule{
					{
						APIGroups: []string{""},
						Resources: []string{"pods"},
						Verbs:     []string{"get", "list"},
					},
				},
			},
			expectedName: "reader",
		},
		{
			name: "cluster role",
			obj: rbacv1.ClusterRole{
				ObjectMeta: metav1.ObjectMeta{
					Name: "cluster-reader",
				},
				Rules: []rbacv1.PolicyRule{
					{
						APIGroups: []string{"apps"},
						Resources: []string{"deployments"},
						Verbs:     []string{"watch"},
					},
				},
			},
			expectedName: "cluster-reader",
		},
		{
			name: "unsupported field type returns marshal error",
			obj: struct {
				Bad func()
			}{
				Bad: func() {},
			},
			expectedError: "unsupported type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := convertToMap(tt.obj)

			if tt.expectedError != "" {
				assert.ErrorContains(t, err, tt.expectedError)
				assert.Nil(t, got)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tt.expectedName, got["metadata"].(map[string]interface{})["name"])
			assert.Contains(t, got, "rules")
		})
	}
}
