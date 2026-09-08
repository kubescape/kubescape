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
			Description:    "lowercase kind preserves casing for bare identifier",
			Input:          "deployment/nginx",
			WantNamespace:  "",
			WantKind:       "deployment",
			WantName:       "nginx",
			WantApiVersion: "",
			WantErr:        false,
		},
		{
			Description:    "uppercase kind preserves casing for bare identifier",
			Input:          "DEPLOYMENT/nginx",
			WantNamespace:  "",
			WantKind:       "DEPLOYMENT",
			WantName:       "nginx",
			WantApiVersion: "",
			WantErr:        false,
		},
		{
			Description:    "mixed-case kind preserves casing for bare identifier",
			Input:          "DePloyment/nginx",
			WantNamespace:  "",
			WantKind:       "DePloyment",
			WantName:       "nginx",
			WantApiVersion: "",
			WantErr:        false,
		},
		{
			Description:    "plural kind preserves casing for bare identifier",
			Input:          "deployments/nginx",
			WantNamespace:  "",
			WantKind:       "deployments",
			WantName:       "nginx",
			WantApiVersion: "",
			WantErr:        false,
		},
		{
			Description:    "plural pods preserves casing for bare identifier",
			Input:          "pods/nginx",
			WantNamespace:  "",
			WantKind:       "pods",
			WantName:       "nginx",
			WantApiVersion: "",
			WantErr:        false,
		},
		{
			Description:    "lowercase daemonset preserves casing for bare identifier",
			Input:          "daemonset/fluentd",
			WantNamespace:  "",
			WantKind:       "daemonset",
			WantName:       "fluentd",
			WantApiVersion: "",
			WantErr:        false,
		},
		{
			Description:    "lowercase statefulset preserves casing for bare identifier",
			Input:          "statefulset/redis",
			WantNamespace:  "",
			WantKind:       "statefulset",
			WantName:       "redis",
			WantApiVersion: "",
			WantErr:        false,
		},
		{
			Description:    "lowercase cronjob preserves casing for bare identifier",
			Input:          "cronjob/backup",
			WantNamespace:  "",
			WantKind:       "cronjob",
			WantName:       "backup",
			WantApiVersion: "",
			WantErr:        false,
		},
		{
			Description:    "short name deploy preserves name for bare identifier",
			Input:          "deploy/nginx",
			WantNamespace:  "",
			WantKind:       "deploy",
			WantName:       "nginx",
			WantApiVersion: "",
			WantErr:        false,
		},
		{
			Description:    "uppercase short name DEPLOY preserves name for bare identifier",
			Input:          "DEPLOY/nginx",
			WantNamespace:  "",
			WantKind:       "DEPLOY",
			WantName:       "nginx",
			WantApiVersion: "",
			WantErr:        false,
		},
		{
			Description:    "short name po preserves name for bare identifier",
			Input:          "po/nginx",
			WantNamespace:  "",
			WantKind:       "po",
			WantName:       "nginx",
			WantApiVersion: "",
			WantErr:        false,
		},
		{
			Description:    "uppercase short name PO preserves name for bare identifier",
			Input:          "PO/nginx",
			WantNamespace:  "",
			WantKind:       "PO",
			WantName:       "nginx",
			WantApiVersion: "",
			WantErr:        false,
		},
		{
			Description:    "short name svc preserves name for bare identifier",
			Input:          "svc/web",
			WantNamespace:  "",
			WantKind:       "svc",
			WantName:       "web",
			WantApiVersion: "",
			WantErr:        false,
		},
		{
			Description:    "uppercase short name SVC preserves name for bare identifier",
			Input:          "SVC/web",
			WantNamespace:  "",
			WantKind:       "SVC",
			WantName:       "web",
			WantApiVersion: "",
			WantErr:        false,
		},
		{
			Description:    "short name ds preserves name for bare identifier",
			Input:          "ds/fluentd",
			WantNamespace:  "",
			WantKind:       "ds",
			WantName:       "fluentd",
			WantApiVersion: "",
			WantErr:        false,
		},
		{
			Description:    "short name sts preserves name for bare identifier",
			Input:          "sts/redis",
			WantNamespace:  "",
			WantKind:       "sts",
			WantName:       "redis",
			WantApiVersion: "",
			WantErr:        false,
		},
		{
			Description:    "short name cj preserves name for bare identifier",
			Input:          "cj/backup",
			WantNamespace:  "",
			WantKind:       "cj",
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
			Description:    "short name with version only normalizes kind",
			Input:          "deploy.v1/nginx",
			WantNamespace:  "",
			WantKind:       "Deployment",
			WantName:       "nginx",
			WantApiVersion: "v1",
			WantErr:        false,
		},
		{
			Description:    "lowercase kind with version only normalizes kind",
			Input:          "deployment.v1/nginx",
			WantNamespace:  "",
			WantKind:       "Deployment",
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
			Description:    "policy resource podsecuritypolicy preserves bare kind",
			Input:          "podsecuritypolicy/restricted",
			WantNamespace:  "",
			WantKind:       "podsecuritypolicy",
			WantName:       "restricted",
			WantApiVersion: "",
			WantErr:        false,
		},
		{
			Description:    "policy short name psp preserves bare kind",
			Input:          "psp/restricted",
			WantNamespace:  "",
			WantKind:       "psp",
			WantName:       "restricted",
			WantApiVersion: "",
			WantErr:        false,
		},
		{
			Description:    "apps resource controllerrevision preserves bare kind",
			Input:          "controllerrevision/rev-1",
			WantNamespace:  "",
			WantKind:       "controllerrevision",
			WantName:       "rev-1",
			WantApiVersion: "",
			WantErr:        false,
		},
		{
			Description:    "policy resource podsecuritypolicy with group normalizes to PascalCase",
			Input:          "podsecuritypolicy.v1beta1.policy/restricted",
			WantNamespace:  "",
			WantKind:       "PodSecurityPolicy",
			WantName:       "restricted",
			WantApiVersion: "policy/v1beta1",
			WantErr:        false,
		},
		{
			Description:    "policy short name psp with group normalizes to PascalCase",
			Input:          "psp.v1beta1.policy/restricted",
			WantNamespace:  "",
			WantKind:       "PodSecurityPolicy",
			WantName:       "restricted",
			WantApiVersion: "policy/v1beta1",
			WantErr:        false,
		},
		{
			Description:    "apps resource controllerrevision with group normalizes to PascalCase",
			Input:          "controllerrevision.v1.apps/rev-1",
			WantNamespace:  "",
			WantKind:       "ControllerRevision",
			WantName:       "rev-1",
			WantApiVersion: "apps/v1",
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
	return IsBuiltinGroup(group)
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
