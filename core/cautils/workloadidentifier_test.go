package cautils

import (
	"strings"
	"testing"

	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseWorkloadIdentifierString_Invalid(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "empty identifier",
			input: "",
		},
		{
			name:  "too many segments",
			input: "cluster/default/Deployment/nginx",
		},
		{
			name:  "empty segment",
			input: "default//nginx",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, _, _, err := ParseWorkloadIdentifierString(tt.input)
			assert.Error(t, err)
		})
	}
}

func TestParseWorkloadIdentifierString_Valid(t *testing.T) {
	t.Run("valid identifier", func(t *testing.T) {
		namespace, kind, name, apiVersion, err := ParseWorkloadIdentifierString("default/Deployment/nginx-deployment")
		assert.NoError(t, err)
		assert.Equal(t, "default", namespace)
		assert.Equal(t, "Deployment", kind)
		assert.Equal(t, "nginx-deployment", name)
		assert.Equal(t, "", apiVersion)
	})
}

func TestParseWorkloadIdentifierString_Values(t *testing.T) {
	testCases := []struct {
		Description    string
		Input          string
		WantNamespace  string
		WantKind       string
		WantName       string
		WantApiVersion string
		WantErr        bool
	}{
		{
			Description:    "valid kind and name",
			Input:          "Deployment/nginx",
			WantNamespace:  "",
			WantKind:       "Deployment",
			WantName:       "nginx",
			WantApiVersion: "",
			WantErr:        false,
		},
		{
			Description:    "lowercase kind is normalized to PascalCase",
			Input:          "deployment/nginx",
			WantNamespace:  "",
			WantKind:       "Deployment",
			WantName:       "nginx",
			WantApiVersion: "",
			WantErr:        false,
		},
		{
			Description:    "uppercase kind is normalized to PascalCase",
			Input:          "DEPLOYMENT/nginx",
			WantNamespace:  "",
			WantKind:       "Deployment",
			WantName:       "nginx",
			WantApiVersion: "",
			WantErr:        false,
		},
		{
			Description:    "mixed-case kind is normalized to PascalCase",
			Input:          "DePloyment/nginx",
			WantNamespace:  "",
			WantKind:       "Deployment",
			WantName:       "nginx",
			WantApiVersion: "",
			WantErr:        false,
		},
		{
			Description:    "plural kind is normalized to PascalCase singular",
			Input:          "deployments/nginx",
			WantNamespace:  "",
			WantKind:       "Deployment",
			WantName:       "nginx",
			WantApiVersion: "",
			WantErr:        false,
		},
		{
			Description:    "plural pods is normalized to Pod",
			Input:          "pods/nginx",
			WantNamespace:  "",
			WantKind:       "Pod",
			WantName:       "nginx",
			WantApiVersion: "",
			WantErr:        false,
		},
		{
			Description:    "lowercase daemonset is normalized to DaemonSet",
			Input:          "daemonset/fluentd",
			WantNamespace:  "",
			WantKind:       "DaemonSet",
			WantName:       "fluentd",
			WantApiVersion: "",
			WantErr:        false,
		},
		{
			Description:    "lowercase statefulset is normalized to StatefulSet",
			Input:          "statefulset/redis",
			WantNamespace:  "",
			WantKind:       "StatefulSet",
			WantName:       "redis",
			WantApiVersion: "",
			WantErr:        false,
		},
		{
			Description:    "lowercase cronjob is normalized to CronJob",
			Input:          "cronjob/backup",
			WantNamespace:  "",
			WantKind:       "CronJob",
			WantName:       "backup",
			WantApiVersion: "",
			WantErr:        false,
		},
		{
			Description:    "short name deploy is normalized to Deployment",
			Input:          "deploy/nginx",
			WantNamespace:  "",
			WantKind:       "Deployment",
			WantName:       "nginx",
			WantApiVersion: "",
			WantErr:        false,
		},
		{
			Description:    "uppercase short name DEPLOY is normalized to Deployment",
			Input:          "DEPLOY/nginx",
			WantNamespace:  "",
			WantKind:       "Deployment",
			WantName:       "nginx",
			WantApiVersion: "",
			WantErr:        false,
		},
		{
			Description:    "short name po is normalized to Pod",
			Input:          "po/nginx",
			WantNamespace:  "",
			WantKind:       "Pod",
			WantName:       "nginx",
			WantApiVersion: "",
			WantErr:        false,
		},
		{
			Description:    "uppercase short name PO is normalized to Pod",
			Input:          "PO/nginx",
			WantNamespace:  "",
			WantKind:       "Pod",
			WantName:       "nginx",
			WantApiVersion: "",
			WantErr:        false,
		},
		{
			Description:    "short name svc is normalized to Service",
			Input:          "svc/web",
			WantNamespace:  "",
			WantKind:       "Service",
			WantName:       "web",
			WantApiVersion: "",
			WantErr:        false,
		},
		{
			Description:    "uppercase short name SVC is normalized to Service",
			Input:          "SVC/web",
			WantNamespace:  "",
			WantKind:       "Service",
			WantName:       "web",
			WantApiVersion: "",
			WantErr:        false,
		},
		{
			Description:    "short name ds is normalized to DaemonSet",
			Input:          "ds/fluentd",
			WantNamespace:  "",
			WantKind:       "DaemonSet",
			WantName:       "fluentd",
			WantApiVersion: "",
			WantErr:        false,
		},
		{
			Description:    "short name sts is normalized to StatefulSet",
			Input:          "sts/redis",
			WantNamespace:  "",
			WantKind:       "StatefulSet",
			WantName:       "redis",
			WantApiVersion: "",
			WantErr:        false,
		},
		{
			Description:    "short name cj is normalized to CronJob",
			Input:          "cj/backup",
			WantNamespace:  "",
			WantKind:       "CronJob",
			WantName:       "backup",
			WantApiVersion: "",
			WantErr:        false,
		},
		{
			Description:    "valid namespace kind and name",
			Input:          "default/Deployment/nginx",
			WantNamespace:  "default",
			WantKind:       "Deployment",
			WantName:       "nginx",
			WantApiVersion: "",
			WantErr:        false,
		},
		{
			Description:    "valid kind.version and name",
			Input:          "Pod.v1/nginx",
			WantNamespace:  "",
			WantKind:       "Pod",
			WantName:       "nginx",
			WantApiVersion: "v1",
			WantErr:        false,
		},
		{
			Description:    "valid kind.version.group and name",
			Input:          "Deployment.v1.apps/nginx",
			WantNamespace:  "",
			WantKind:       "Deployment",
			WantName:       "nginx",
			WantApiVersion: "apps/v1",
			WantErr:        false,
		},
		{
			Description:    "lowercase kind with dotted apiVersion is normalized",
			Input:          "deployment.v1.apps/nginx",
			WantNamespace:  "",
			WantKind:       "Deployment",
			WantName:       "nginx",
			WantApiVersion: "apps/v1",
			WantErr:        false,
		},
		{
			Description:    "valid namespace kind.version.group and name",
			Input:          "default/Deployment.v1.apps/nginx",
			WantNamespace:  "default",
			WantKind:       "Deployment",
			WantName:       "nginx",
			WantApiVersion: "apps/v1",
			WantErr:        false,
		},
		{
			Description:    "valid multi-label group",
			Input:          "Ingress.v1.networking.k8s.io/name",
			WantNamespace:  "",
			WantKind:       "Ingress",
			WantName:       "name",
			WantApiVersion: "networking.k8s.io/v1",
			WantErr:        false,
		},
		{
			Description:    "unknown CRD kind preserves casing",
			Input:          "customcrd/my-cr",
			WantNamespace:  "",
			WantKind:       "customcrd",
			WantName:       "my-cr",
			WantApiVersion: "",
			WantErr:        false,
		},
		{
			Description:    "unknown CRD kind with PascalCase preserves casing",
			Input:          "MyCustomResource/my-cr",
			WantNamespace:  "",
			WantKind:       "MyCustomResource",
			WantName:       "my-cr",
			WantApiVersion: "",
			WantErr:        false,
		},
		{
			Description:    "custom CRD kind matching alias in custom API group preserves original casing",
			Input:          "Deploy.v1.example.com/name",
			WantNamespace:  "",
			WantKind:       "Deploy",
			WantName:       "name",
			WantApiVersion: "example.com/v1",
			WantErr:        false,
		},
		{
			Description:    "custom CRD kind matching lowercase alias in custom API group preserves original casing",
			Input:          "deploy.v1.example.com/name",
			WantNamespace:  "",
			WantKind:       "deploy",
			WantName:       "name",
			WantApiVersion: "example.com/v1",
			WantErr:        false,
		},
		{
			Description:    "custom CRD kind matching alias in custom .k8s.io API group preserves original casing",
			Input:          "Deploy.v1.example.k8s.io/name",
			WantNamespace:  "",
			WantKind:       "Deploy",
			WantName:       "name",
			WantApiVersion: "example.k8s.io/v1",
			WantErr:        false,
		},
		{
			Description:    "custom CRD kind matching lowercase alias in custom .k8s.io API group preserves original casing",
			Input:          "deploy.v1.example.k8s.io/name",
			WantNamespace:  "",
			WantKind:       "deploy",
			WantName:       "name",
			WantApiVersion: "example.k8s.io/v1",
			WantErr:        false,
		},
		{
			Description:    "built-in alias in built-in API group normalizes to PascalCase",
			Input:          "deploy.v1.apps/name",
			WantNamespace:  "",
			WantKind:       "Deployment",
			WantName:       "name",
			WantApiVersion: "apps/v1",
			WantErr:        false,
		},
		{
			Description:    "built-in kind in built-in API group normalizes to PascalCase",
			Input:          "deployment.v1.apps/name",
			WantNamespace:  "",
			WantKind:       "Deployment",
			WantName:       "name",
			WantApiVersion: "apps/v1",
			WantErr:        false,
		},
		{
			Description:    "policy resource podsecuritypolicy normalizes",
			Input:          "podsecuritypolicy/restricted",
			WantNamespace:  "",
			WantKind:       "PodSecurityPolicy",
			WantName:       "restricted",
			WantApiVersion: "",
			WantErr:        false,
		},
		{
			Description:    "policy short name psp normalizes",
			Input:          "psp/restricted",
			WantNamespace:  "",
			WantKind:       "PodSecurityPolicy",
			WantName:       "restricted",
			WantApiVersion: "",
			WantErr:        false,
		},
		{
			Description:    "apps resource controllerrevision normalizes",
			Input:          "controllerrevision/rev-1",
			WantNamespace:  "",
			WantKind:       "ControllerRevision",
			WantName:       "rev-1",
			WantApiVersion: "",
			WantErr:        false,
		},
		{
			Description: "invalid empty dotted component",
			Input:       "Deployment..apps/nginx",
			WantErr:     true,
		},
		{
			Description: "invalid empty trailing component",
			Input:       "Deployment./nginx",
			WantErr:     true,
		},
		{
			Description: "invalid missing apiVersion",
			Input:       "Deployment.apps/nginx",
			WantErr:     true,
		},
		{
			Description: "invalid apiVersion segment",
			Input:       "Deployment.bogus/nginx",
			WantErr:     true,
		},
		{
			Description: "too many segments",
			Input:       "cluster/default/Deployment/nginx",
			WantErr:     true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Description, func(t *testing.T) {
			namespace, kind, name, apiVersion, err := ParseWorkloadIdentifierString(tc.Input)
			if tc.WantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tc.WantNamespace, namespace)
			assert.Equal(t, tc.WantKind, kind)
			assert.Equal(t, tc.WantName, name)
			assert.Equal(t, tc.WantApiVersion, apiVersion)
		})
	}
}

func isBuiltinK8sGroup(group string) bool {
	if group == "metrics.k8s.io" {
		return false
	}
	return isBuiltinGroup(group)
}

func TestNormalizeWorkloadKind_MockDriftCheck(t *testing.T) {
	resourceLists, err := k8sinterface.GetResourceListMock()
	require.NoError(t, err)
	require.NotEmpty(t, resourceLists)

	for _, list := range resourceLists {
		if list == nil {
			continue
		}
		// Parse group
		group := ""
		if parts := strings.Split(list.GroupVersion, "/"); len(parts) > 1 {
			group = parts[0]
		}
		if !isBuiltinK8sGroup(group) {
			continue
		}

		for _, resource := range list.APIResources {
			if resource.Kind == "" || strings.Contains(resource.Name, "/") {
				continue
			}
			// Direction: Mock -> Map (every Kind from built-in mock resolves to its canonical PascalCase Kind)
			normalized := NormalizeWorkloadKind(strings.ToLower(resource.Kind))
			assert.Equalf(t, resource.Kind, normalized, "Kind %q (group %q) from mock failed to normalize", resource.Kind, list.GroupVersion)

			if resource.Name != "" {
				normalizedName := NormalizeWorkloadKind(strings.ToLower(resource.Name))
				assert.Equalf(t, resource.Kind, normalizedName, "Plural name %q for Kind %q (group %q) failed to normalize", resource.Name, resource.Kind, list.GroupVersion)
			}
		}
	}

	// Verify that unknown kinds remain unchanged
	assert.Equal(t, "MyUnknownCRD", NormalizeWorkloadKind("MyUnknownCRD"))
	assert.Equal(t, "myunknowncrd", NormalizeWorkloadKind("myunknowncrd"))
}
