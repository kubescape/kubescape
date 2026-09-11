package cautils

import (
	"errors"
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
		{
			name:  "uppercase name",
			input: "Deployment/NGINX",
		},
		{
			name:  "name with symbols",
			input: "Deployment/nginx@latest",
		},
		{
			name:  "name with spaces",
			input: "Deployment/my nginx",
		},
		{
			name:  "name with underscores",
			input: "Deployment/nginx_app",
		},
		{
			name:  "name with leading hyphen",
			input: "Deployment/-nginx",
		},
		{
			name:  "name with trailing dot",
			input: "Deployment/nginx.",
		},
		{
			name:  "kind with symbol",
			input: "Deploy!/nginx",
		},
		{
			name:  "kind with space",
			input: "Deploy ment/nginx",
		},
		{
			name:  "kind with leading hyphen",
			input: "-Pod/nginx",
		},
		{
			name:  "kind with trailing hyphen",
			input: "Pod-/nginx",
		},
		{
			name:  "kind with leading digit",
			input: "1Pod/nginx",
		},
		{
			name:  "kind with leading hyphen",
			input: "-Pod/nginx",
		},
		{
			name:  "RBAC name with percent",
			input: "ClusterRole/system%discovery",
		},
		{
			name:  "RBAC name dot",
			input: "ClusterRole/.",
		},
		{
			name:  "RBAC name dotdot",
			input: "ClusterRole/..",
		},
		{
			name:  "invalid namespace uppercase",
			input: "Default/Deployment/nginx",
		},
		{
			name:  "invalid namespace dots",
			input: "my.ns/Deployment/nginx",
		},
		{
			name:  "invalid namespace symbols",
			input: "ns_prod/Deployment/nginx",
		},
		{
			name:  "invalid API group symbols",
			input: "Deployment.v1.apps@bad/nginx",
		},
		{
			name:  "invalid API group spaces",
			input: "Deployment.v1.apps core/nginx",
		},
		{
			name:  "Deployment with colon name is rejected",
			input: "Deployment/example.com:foo:abc",
		},
		{
			name:  "qualified Deployment with colon name is rejected",
			input: "Deployment.v1.apps/example.com:foo:abc",
		},
		{
			name:  "ClusterTrustBundle with empty bundle name",
			input: "ClusterTrustBundle.v1.certificates.k8s.io/example.com:foo:",
		},
		{
			name:  "ClusterTrustBundle with empty domain",
			input: "ClusterTrustBundle.v1.certificates.k8s.io/:foo:abc",
		},
		{
			name:  "ClusterTrustBundle with empty path",
			input: "ClusterTrustBundle.v1.certificates.k8s.io/example.com::abc",
		},
		{
			name:  "ClusterTrustBundle domain without dot",
			input: "ClusterTrustBundle.v1.certificates.k8s.io/examplecom:foo:abc",
		},
		{
			name:  "ClusterTrustBundle too many colons in signer prefix",
			input: "ClusterTrustBundle.v1.certificates.k8s.io/example.com:foo:abc:extra",
		},
		{
			name:  "ClusterTrustBundle with uppercase in bundle name",
			input: "ClusterTrustBundle.v1.certificates.k8s.io/example.com:foo:ABC",
		},
		{
			name:  "CertificateSigningRequest with unrelated custom group rejects colon name",
			input: "CertificateSigningRequest.v1.example.com/client:alice",
		},
		{
			name:  "csr alias with unrelated custom group rejects colon name",
			input: "csr.v1.example.com/client:alice",
		},
		{
			name:  "CertificateSigningRequest with invalid dot path segment name",
			input: "CertificateSigningRequest.v1.certificates.k8s.io/.",
		},
		{
			name:  "CertificateSigningRequest with invalid double dot path segment name",
			input: "CertificateSigningRequest.v1.certificates.k8s.io/..",
		},
		{
			name:  "CertificateSigningRequest with invalid percent path segment name",
			input: "CertificateSigningRequest.v1.certificates.k8s.io/client%alice",
		},
		{
			name:  "APIService with invalid dot path segment name",
			input: "APIService.v1.apiregistration.k8s.io/.",
		},
		{
			name:  "APIService with invalid percent path segment name",
			input: "APIService.v1.apiregistration.k8s.io/v1%",
		},
		{
			name:  "APIService with invalid characters in version",
			input: "APIService.v1.apiregistration.k8s.io/v1_bad.",
		},
		{
			name:  "IPAddress with invalid IP address name",
			input: "IPAddress.v1.networking.k8s.io/not-an-ip",
		},
		{
			name:  "IPAddress with invalid percent in name",
			input: "IPAddress.v1.networking.k8s.io/2001%db8",
		},
		{
			name:  "IPAddress with non-canonical uppercase IPv6 address name",
			input: "IPAddress.v1.networking.k8s.io/2001:DB8::1",
		},
		{
			name:  "IPAddress with non-canonical expanded IPv6 address name",
			input: "IPAddress.v1.networking.k8s.io/2001:0db8:0000:0000:0000:0000:0000:0001",
		},
		{
			name:  "Custom resource with non-builtin group and uppercase in name",
			input: "Custom.v1.example.com/UPPER_CASE",
		},
		{
			name:  "Custom resource with non-builtin group and underscore in name",
			input: "Custom.v1.example.com/bad_name",
		},
		{
			name:  "Bare custom resource with uppercase in name",
			input: "Custom/UPPER_CASE",
		},
		{
			name:  "Bare custom resource with underscore in name",
			input: "Custom/bad_name",
		},
		{
			name:  "Event v1 with invalid percent in path segment name",
			input: "Event.v1/event%legacy",
		},
		{
			name:  "Event v1 with invalid dot path segment name",
			input: "Event.v1/.",
		},
		{
			name:  "Event v1 with invalid double dot path segment name",
			input: "Event.v1/..",
		},
		{
			name:  "Event with custom group and colon in name rejected by DNS-1123",
			input: "Event.v1.example.com/event:legacy",
		},
		{
			name:  "Event with events.k8s.io group and invalid percent in path segment name",
			input: "Event.v1.events.k8s.io/event%legacy",
		},
		{
			name:  "Event with events.k8s.io group and invalid dot path segment name",
			input: "Event.v1.events.k8s.io/.",
		},
		{
			name:  "Event with events.k8s.io group and invalid double dot path segment name",
			input: "Event.v1.events.k8s.io/..",
		},
		{
			name:  "APIService with built-in group and invalid standard name",
			input: "APIService.v1.apiregistration.k8s.io/my-api",
		},
		{
			name:  "Bare APIService with invalid percent in path segment name",
			input: "APIService/my%api",
		},
		{
			name:  "Bare APIService with invalid dot path segment name",
			input: "APIService/.",
		},
		{
			name:  "IPAddress with built-in group and invalid IP name",
			input: "IPAddress.v1.networking.k8s.io/my-address",
		},
		{
			name:  "Bare IPAddress with invalid percent in path segment name",
			input: "IPAddress/my%address",
		},
		{
			name:  "Bare IPAddress with invalid dot path segment name",
			input: "IPAddress/.",
		},
		{
			name:  "ClusterTrustBundle with built-in group and invalid single colon name",
			input: "ClusterTrustBundle.v1.certificates.k8s.io/singlecolon:name",
		},
		{
			name:  "ClusterTrustBundle with custom group and colon in name rejected by DNS-1123",
			input: "ClusterTrustBundle.v1.example.com/singlecolon:name",
		},
		{
			name:  "Bare ClusterTrustBundle with invalid percent in path segment name",
			input: "ClusterTrustBundle/my%bundle",
		},
		{
			name:  "Bare ClusterTrustBundle with invalid dot path segment name",
			input: "ClusterTrustBundle/.",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, _, _, err := ParseWorkloadIdentifierString(tt.input)
			assert.Error(t, err)
			assert.True(t, errors.Is(err, ErrInvalidWorkloadIdentifier), "error must wrap ErrInvalidWorkloadIdentifier")
		})
	}
}

func TestParseWorkloadIdentifierString_SentinelErrorWrapping(t *testing.T) {
	tests := []struct {
		domain string
		input  string
		errMsg string
	}{
		{
			domain: "name",
			input:  "Deployment/nginx@latest",
			errMsg: "invalid workload name",
		},
		{
			domain: "kind",
			input:  "Deploy!/nginx",
			errMsg: "invalid workload kind",
		},
		{
			domain: "group",
			input:  "Deployment.v1.apps@bad/nginx",
			errMsg: "invalid API group",
		},
		{
			domain: "namespace",
			input:  "Prod!/Deployment/nginx",
			errMsg: "invalid namespace",
		},
		{
			domain: "rbac-name",
			input:  "ClusterRole/system%discovery",
			errMsg: "invalid workload name",
		},
		{
			domain: "ipaddress-non-canonical",
			input:  "IPAddress.v1.networking.k8s.io/2001:DB8::1",
			errMsg: "is not a canonical IP address",
		},
	}

	for _, tt := range tests {
		t.Run(tt.domain, func(t *testing.T) {
			_, _, _, _, err := ParseWorkloadIdentifierString(tt.input)
			require.Error(t, err)
			assert.True(t, errors.Is(err, ErrInvalidWorkloadIdentifier), "must wrap ErrInvalidWorkloadIdentifier sentinel")
			assert.Contains(t, err.Error(), tt.errMsg)
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
		{
			Description:    "valid name boundary 253 chars",
			Input:          "Deployment/" + strings.Repeat("a", 253),
			WantNamespace:  "",
			WantKind:       "Deployment",
			WantName:       strings.Repeat("a", 253),
			WantApiVersion: "",
			WantErr:        false,
		},
		{
			Description: "invalid name boundary 254 chars",
			Input:       "Deployment/" + strings.Repeat("a", 254),
			WantErr:     true,
		},
		{
			Description:    "valid namespace boundary 63 chars",
			Input:          strings.Repeat("a", 63) + "/Deployment/nginx",
			WantNamespace:  strings.Repeat("a", 63),
			WantKind:       "Deployment",
			WantName:       "nginx",
			WantApiVersion: "",
			WantErr:        false,
		},
		{
			Description: "invalid namespace boundary 64 chars",
			Input:       strings.Repeat("a", 64) + "/Deployment/nginx",
			WantErr:     true,
		},
		{
			Description:    "valid multi-segment CRD domain group",
			Input:          "Custom.v1alpha1.custom.sub.domain.example.com/my-cr",
			WantNamespace:  "",
			WantKind:       "Custom",
			WantName:       "my-cr",
			WantApiVersion: "custom.sub.domain.example.com/v1alpha1",
			WantErr:        false,
		},
		{
			Description: "invalid multi-segment CRD domain group with symbol",
			Input:       "Custom.v1alpha1.custom.sub@domain.example.com/my-cr",
			WantErr:     true,
		},
		{
			Description:    "misspelled kind passes parser format validation (typo tradeoff)",
			Input:          "Deploymnet/nginx",
			WantNamespace:  "",
			WantKind:       "Deploymnet",
			WantName:       "nginx",
			WantApiVersion: "",
			WantErr:        false,
		},
		{
			Description:    "valid hyphenated CRD kind preserves casing",
			Input:          "Pod-App/nginx",
			WantNamespace:  "",
			WantKind:       "Pod-App",
			WantName:       "nginx",
			WantApiVersion: "",
			WantErr:        false,
		},
		{
			Description:    "valid hyphenated CRD kind with custom API group preserves casing",
			Input:          "Pod-App.v1.example.com/nginx",
			WantNamespace:  "",
			WantKind:       "Pod-App",
			WantName:       "nginx",
			WantApiVersion: "example.com/v1",
			WantErr:        false,
		},
		{
			Description:    "valid hyphenated CRD kind with namespace and custom API group preserves casing",
			Input:          "default/Pod-App.v1.example.com/nginx",
			WantNamespace:  "default",
			WantKind:       "Pod-App",
			WantName:       "nginx",
			WantApiVersion: "example.com/v1",
			WantErr:        false,
		},
		{
			Description:    "valid alphanumeric CRD kind preserves casing",
			Input:          "PodApp/nginx",
			WantNamespace:  "",
			WantKind:       "PodApp",
			WantName:       "nginx",
			WantApiVersion: "",
			WantErr:        false,
		},
		{
			Description:    "valid alphanumeric CRD kind with custom API group preserves casing",
			Input:          "PodApp.v1.example.com/nginx",
			WantNamespace:  "",
			WantKind:       "PodApp",
			WantName:       "nginx",
			WantApiVersion: "example.com/v1",
			WantErr:        false,
		},
		{
			Description: "CRD kind with leading digit rejected",
			Input:       "1Pod/nginx",
			WantErr:     true,
		},
		{
			Description:    "valid live RBAC clusterrole with path segment name containing colon",
			Input:          "ClusterRole.v1.rbac.authorization.k8s.io/system:discovery",
			WantNamespace:  "",
			WantKind:       "ClusterRole",
			WantName:       "system:discovery",
			WantApiVersion: "rbac.authorization.k8s.io/v1",
			WantErr:        false,
		},
		{
			Description:    "valid bare RBAC clusterrole with colon name",
			Input:          "ClusterRole/system:discovery",
			WantNamespace:  "",
			WantKind:       "ClusterRole",
			WantName:       "system:discovery",
			WantApiVersion: "",
			WantErr:        false,
		},
		{
			Description:    "valid lowercase bare RBAC clusterrole with colon name",
			Input:          "clusterrole/system:discovery",
			WantNamespace:  "",
			WantKind:       "clusterrole",
			WantName:       "system:discovery",
			WantApiVersion: "",
			WantErr:        false,
		},
		{
			Description:    "valid RBAC role in namespace with hyphenated and colon name",
			Input:          "kube-system/Role.v1.rbac.authorization.k8s.io/extension-apiserver-authentication-reader",
			WantNamespace:  "kube-system",
			WantKind:       "Role",
			WantName:       "extension-apiserver-authentication-reader",
			WantApiVersion: "rbac.authorization.k8s.io/v1",
			WantErr:        false,
		},
		{
			Description:    "valid bare RBAC role with controller colon name",
			Input:          "Role/system:controller:token-cleaner",
			WantNamespace:  "",
			WantKind:       "Role",
			WantName:       "system:controller:token-cleaner",
			WantApiVersion: "",
			WantErr:        false,
		},
		{
			Description:    "valid bare RBAC rolebinding with controller colon name",
			Input:          "RoleBinding/system:controller:token-cleaner",
			WantNamespace:  "",
			WantKind:       "RoleBinding",
			WantName:       "system:controller:token-cleaner",
			WantApiVersion: "",
			WantErr:        false,
		},
		{
			Description:    "valid bare RBAC clusterrolebinding with colon name",
			Input:          "ClusterRoleBinding/system:discovery",
			WantNamespace:  "",
			WantKind:       "ClusterRoleBinding",
			WantName:       "system:discovery",
			WantApiVersion: "",
			WantErr:        false,
		},
		{
			Description:    "valid live ClusterTrustBundle v1 with signer colon name",
			Input:          "ClusterTrustBundle.v1.certificates.k8s.io/example.com:foo:abc",
			WantNamespace:  "",
			WantKind:       "ClusterTrustBundle",
			WantName:       "example.com:foo:abc",
			WantApiVersion: "certificates.k8s.io/v1",
			WantErr:        false,
		},
		{
			Description:    "valid live ClusterTrustBundle v1beta1 with signer colon name",
			Input:          "ClusterTrustBundle.v1beta1.certificates.k8s.io/example.com:foo:abc",
			WantNamespace:  "",
			WantKind:       "ClusterTrustBundle",
			WantName:       "example.com:foo:abc",
			WantApiVersion: "certificates.k8s.io/v1beta1",
			WantErr:        false,
		},
		{
			Description:    "valid live ClusterTrustBundle v1alpha1 with signer colon name",
			Input:          "ClusterTrustBundle.v1alpha1.certificates.k8s.io/example.com:foo:abc",
			WantNamespace:  "",
			WantKind:       "ClusterTrustBundle",
			WantName:       "example.com:foo:abc",
			WantApiVersion: "certificates.k8s.io/v1alpha1",
			WantErr:        false,
		},
		{
			Description:    "valid bare ClusterTrustBundle with signer colon name",
			Input:          "ClusterTrustBundle/example.com:foo:abc",
			WantNamespace:  "",
			WantKind:       "ClusterTrustBundle",
			WantName:       "example.com:foo:abc",
			WantApiVersion: "",
			WantErr:        false,
		},
		{
			Description:    "valid lowercase bare clustertrustbundle with signer colon name",
			Input:          "clustertrustbundle/example.com:foo:abc",
			WantNamespace:  "",
			WantKind:       "clustertrustbundle",
			WantName:       "example.com:foo:abc",
			WantApiVersion: "",
			WantErr:        false,
		},
		{
			Description:    "valid short name ctb with signer colon name",
			Input:          "ctb/example.com:foo:abc",
			WantNamespace:  "",
			WantKind:       "ctb",
			WantName:       "example.com:foo:abc",
			WantApiVersion: "",
			WantErr:        false,
		},
		{
			Description:    "valid bare ClusterTrustBundle without signer name",
			Input:          "ClusterTrustBundle/my-root-ca",
			WantNamespace:  "",
			WantKind:       "ClusterTrustBundle",
			WantName:       "my-root-ca",
			WantApiVersion: "",
			WantErr:        false,
		},
		{
			Description:    "valid ClusterTrustBundle with dotted path in signer",
			Input:          "ClusterTrustBundle.v1.certificates.k8s.io/example.com:foo.bar:my-bundle",
			WantNamespace:  "",
			WantKind:       "ClusterTrustBundle",
			WantName:       "example.com:foo.bar:my-bundle",
			WantApiVersion: "certificates.k8s.io/v1",
			WantErr:        false,
		},
		{
			Description:    "valid live CertificateSigningRequest v1 with colon name",
			Input:          "CertificateSigningRequest.v1.certificates.k8s.io/client:alice",
			WantNamespace:  "",
			WantKind:       "CertificateSigningRequest",
			WantName:       "client:alice",
			WantApiVersion: "certificates.k8s.io/v1",
			WantErr:        false,
		},
		{
			Description:    "valid live csr alias v1 with colon name",
			Input:          "csr.v1.certificates.k8s.io/client:alice",
			WantNamespace:  "",
			WantKind:       "CertificateSigningRequest",
			WantName:       "client:alice",
			WantApiVersion: "certificates.k8s.io/v1",
			WantErr:        false,
		},
		{
			Description:    "valid live CertificateSigningRequest v1beta1 with colon name",
			Input:          "CertificateSigningRequest.v1beta1.certificates.k8s.io/client:alice",
			WantNamespace:  "",
			WantKind:       "CertificateSigningRequest",
			WantName:       "client:alice",
			WantApiVersion: "certificates.k8s.io/v1beta1",
			WantErr:        false,
		},
		{
			Description:    "valid bare CertificateSigningRequest with colon name",
			Input:          "CertificateSigningRequest/client:alice",
			WantNamespace:  "",
			WantKind:       "CertificateSigningRequest",
			WantName:       "client:alice",
			WantApiVersion: "",
			WantErr:        false,
		},
		{
			Description:    "valid bare csr alias with colon name",
			Input:          "csr/client:alice",
			WantNamespace:  "",
			WantKind:       "csr",
			WantName:       "client:alice",
			WantApiVersion: "",
			WantErr:        false,
		},
		{
			Description:    "valid live APIService v1 with core trailing dot name",
			Input:          "APIService.v1.apiregistration.k8s.io/v1.",
			WantNamespace:  "",
			WantKind:       "APIService",
			WantName:       "v1.",
			WantApiVersion: "apiregistration.k8s.io/v1",
			WantErr:        false,
		},
		{
			Description:    "valid live APIService v1 with group name",
			Input:          "APIService.v1.apiregistration.k8s.io/v1.apps",
			WantNamespace:  "",
			WantKind:       "APIService",
			WantName:       "v1.apps",
			WantApiVersion: "apiregistration.k8s.io/v1",
			WantErr:        false,
		},
		{
			Description:    "valid bare APIService with trailing dot name",
			Input:          "APIService/v1.",
			WantNamespace:  "",
			WantKind:       "APIService",
			WantName:       "v1.",
			WantApiVersion: "",
			WantErr:        false,
		},
		{
			Description:    "valid bare apiservice alias with trailing dot name",
			Input:          "apiservice/v1.",
			WantNamespace:  "",
			WantKind:       "apiservice",
			WantName:       "v1.",
			WantApiVersion: "",
			WantErr:        false,
		},
		{
			Description:    "valid live IPAddress v1 with IPv6 address name",
			Input:          "IPAddress.v1.networking.k8s.io/2001:db8::1",
			WantNamespace:  "",
			WantKind:       "IPAddress",
			WantName:       "2001:db8::1",
			WantApiVersion: "networking.k8s.io/v1",
			WantErr:        false,
		},
		{
			Description:    "valid live IPAddress v1 with IPv4 address name",
			Input:          "IPAddress.v1.networking.k8s.io/192.0.2.1",
			WantNamespace:  "",
			WantKind:       "IPAddress",
			WantName:       "192.0.2.1",
			WantApiVersion: "networking.k8s.io/v1",
			WantErr:        false,
		},
		{
			Description:    "valid bare IPAddress with IPv6 address name",
			Input:          "IPAddress/2001:db8::1",
			WantNamespace:  "",
			WantKind:       "IPAddress",
			WantName:       "2001:db8::1",
			WantApiVersion: "",
			WantErr:        false,
		},
		{
			Description:    "valid bare ipaddress alias with IPv6 address name",
			Input:          "ipaddress/2001:db8::1",
			WantNamespace:  "",
			WantKind:       "ipaddress",
			WantName:       "2001:db8::1",
			WantApiVersion: "",
			WantErr:        false,
		},
		{
			Description:    "valid custom resource with non-builtin group and lowercase name",
			Input:          "Custom.v1.example.com/my-cr-name",
			WantNamespace:  "",
			WantKind:       "Custom",
			WantName:       "my-cr-name",
			WantApiVersion: "example.com/v1",
			WantErr:        false,
		},
		{
			Description:    "valid bare custom resource with lowercase name",
			Input:          "Custom/my-cr-name",
			WantNamespace:  "",
			WantKind:       "Custom",
			WantName:       "my-cr-name",
			WantApiVersion: "",
			WantErr:        false,
		},
		{
			Description:    "valid live Event v1 with colon name",
			Input:          "Event.v1/event:legacy",
			WantNamespace:  "",
			WantKind:       "Event",
			WantName:       "event:legacy",
			WantApiVersion: "v1",
			WantErr:        false,
		},
		{
			Description:    "valid live event alias with colon name",
			Input:          "ev.v1/event:legacy",
			WantNamespace:  "",
			WantKind:       "Event",
			WantName:       "event:legacy",
			WantApiVersion: "v1",
			WantErr:        false,
		},
		{
			Description:    "valid bare Event with colon name",
			Input:          "Event/event:legacy",
			WantNamespace:  "",
			WantKind:       "Event",
			WantName:       "event:legacy",
			WantApiVersion: "",
			WantErr:        false,
		},
		{
			Description:    "valid bare events alias with colon name",
			Input:          "events/event:legacy",
			WantNamespace:  "",
			WantKind:       "events",
			WantName:       "event:legacy",
			WantApiVersion: "",
			WantErr:        false,
		},
		{
			Description:    "valid bare ev alias with colon name",
			Input:          "ev/event:legacy",
			WantNamespace:  "",
			WantKind:       "ev",
			WantName:       "event:legacy",
			WantApiVersion: "",
			WantErr:        false,
		},
		{
			Description:    "valid namespace-qualified Event v1 with colon name",
			Input:          "default/Event.v1/event:legacy",
			WantNamespace:  "default",
			WantKind:       "Event",
			WantName:       "event:legacy",
			WantApiVersion: "v1",
			WantErr:        false,
		},
		{
			Description:    "valid live Event v1 with events.k8s.io group and colon name",
			Input:          "Event.v1.events.k8s.io/event:legacy",
			WantNamespace:  "",
			WantKind:       "Event",
			WantName:       "event:legacy",
			WantApiVersion: "events.k8s.io/v1",
			WantErr:        false,
		},
		{
			Description:    "valid live event alias with events.k8s.io group and colon name",
			Input:          "ev.v1.events.k8s.io/event:legacy",
			WantNamespace:  "",
			WantKind:       "Event",
			WantName:       "event:legacy",
			WantApiVersion: "events.k8s.io/v1",
			WantErr:        false,
		},
		{
			Description:    "valid live events alias with events.k8s.io group and colon name",
			Input:          "events.v1.events.k8s.io/event:legacy",
			WantNamespace:  "",
			WantKind:       "Event",
			WantName:       "event:legacy",
			WantApiVersion: "events.k8s.io/v1",
			WantErr:        false,
		},
		{
			Description:    "valid live Event v1beta1 with events.k8s.io group and colon name",
			Input:          "Event.v1beta1.events.k8s.io/event:legacy",
			WantNamespace:  "",
			WantKind:       "Event",
			WantName:       "event:legacy",
			WantApiVersion: "events.k8s.io/v1beta1",
			WantErr:        false,
		},
		{
			Description:    "valid namespace-qualified Event v1 with events.k8s.io group and colon name",
			Input:          "default/Event.v1.events.k8s.io/event:legacy",
			WantNamespace:  "default",
			WantKind:       "Event",
			WantName:       "event:legacy",
			WantApiVersion: "events.k8s.io/v1",
			WantErr:        false,
		},
		{
			Description:    "valid live Event v1 with custom group and standard name",
			Input:          "Event.v1.example.com/my-event",
			WantNamespace:  "",
			WantKind:       "Event",
			WantName:       "my-event",
			WantApiVersion: "example.com/v1",
			WantErr:        false,
		},
		{
			Description:    "valid bare APIService with custom resource name",
			Input:          "APIService/my-api",
			WantNamespace:  "",
			WantKind:       "APIService",
			WantName:       "my-api",
			WantApiVersion: "",
			WantErr:        false,
		},
		{
			Description:    "valid bare apiservice alias with custom resource name",
			Input:          "apiservice/my-api",
			WantNamespace:  "",
			WantKind:       "apiservice",
			WantName:       "my-api",
			WantApiVersion: "",
			WantErr:        false,
		},
		{
			Description:    "valid APIService with version only and custom resource name",
			Input:          "APIService.v1/my-api",
			WantNamespace:  "",
			WantKind:       "APIService",
			WantName:       "my-api",
			WantApiVersion: "v1",
			WantErr:        false,
		},
		{
			Description:    "valid APIService with v2 version only and custom resource name",
			Input:          "APIService.v2/my-api",
			WantNamespace:  "",
			WantKind:       "APIService",
			WantName:       "my-api",
			WantApiVersion: "v2",
			WantErr:        false,
		},
		{
			Description:    "valid APIService with custom group and name",
			Input:          "APIService.v1.example.com/my-api",
			WantNamespace:  "",
			WantKind:       "APIService",
			WantName:       "my-api",
			WantApiVersion: "example.com/v1",
			WantErr:        false,
		},
		{
			Description:    "valid bare IPAddress with custom resource name",
			Input:          "IPAddress/my-address",
			WantNamespace:  "",
			WantKind:       "IPAddress",
			WantName:       "my-address",
			WantApiVersion: "",
			WantErr:        false,
		},
		{
			Description:    "valid bare ipaddress alias with custom resource name",
			Input:          "ipaddress/my-address",
			WantNamespace:  "",
			WantKind:       "ipaddress",
			WantName:       "my-address",
			WantApiVersion: "",
			WantErr:        false,
		},
		{
			Description:    "valid IPAddress with version only and custom resource name",
			Input:          "IPAddress.v1/my-address",
			WantNamespace:  "",
			WantKind:       "IPAddress",
			WantName:       "my-address",
			WantApiVersion: "v1",
			WantErr:        false,
		},
		{
			Description:    "valid IPAddress with v2 version only and custom resource name",
			Input:          "IPAddress.v2/my-address",
			WantNamespace:  "",
			WantKind:       "IPAddress",
			WantName:       "my-address",
			WantApiVersion: "v2",
			WantErr:        false,
		},
		{
			Description:    "valid IPAddress with custom group and name",
			Input:          "IPAddress.v1.example.com/my-address",
			WantNamespace:  "",
			WantKind:       "IPAddress",
			WantName:       "my-address",
			WantApiVersion: "example.com/v1",
			WantErr:        false,
		},
		{
			Description:    "valid bare ClusterTrustBundle with custom resource name",
			Input:          "ClusterTrustBundle/my-bundle",
			WantNamespace:  "",
			WantKind:       "ClusterTrustBundle",
			WantName:       "my-bundle",
			WantApiVersion: "",
			WantErr:        false,
		},
		{
			Description:    "valid bare ctb alias with custom resource name",
			Input:          "ctb/my-bundle",
			WantNamespace:  "",
			WantKind:       "ctb",
			WantName:       "my-bundle",
			WantApiVersion: "",
			WantErr:        false,
		},
		{
			Description:    "valid ClusterTrustBundle with version only and custom resource name",
			Input:          "ClusterTrustBundle.v1/my-bundle",
			WantNamespace:  "",
			WantKind:       "ClusterTrustBundle",
			WantName:       "my-bundle",
			WantApiVersion: "v1",
			WantErr:        false,
		},
		{
			Description:    "valid ClusterTrustBundle with built-in group and unlinked name",
			Input:          "ClusterTrustBundle.v1.certificates.k8s.io/my-bundle",
			WantNamespace:  "",
			WantKind:       "ClusterTrustBundle",
			WantName:       "my-bundle",
			WantApiVersion: "certificates.k8s.io/v1",
			WantErr:        false,
		},
		{
			Description:    "valid ClusterTrustBundle with custom group and name",
			Input:          "ClusterTrustBundle.v1.example.com/my-bundle",
			WantNamespace:  "",
			WantKind:       "ClusterTrustBundle",
			WantName:       "my-bundle",
			WantApiVersion: "example.com/v1",
			WantErr:        false,
		},
		{
			Description:    "valid bare ClusterTrustBundle with colon name",
			Input:          "ClusterTrustBundle/singlecolon:name",
			WantNamespace:  "",
			WantKind:       "ClusterTrustBundle",
			WantName:       "singlecolon:name",
			WantApiVersion: "",
			WantErr:        false,
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

func TestResolveWorkloadNamespace(t *testing.T) {
	tests := []struct {
		name              string
		identNamespace    string
		explicitNamespace string
		isClusterScan     bool
		wantNamespace     string
		wantDefaulted     bool
		wantErr           string
	}{
		{
			name:              "cluster scan: both omitted defaults to default",
			identNamespace:    "",
			explicitNamespace: "",
			isClusterScan:     true,
			wantNamespace:     "default",
			wantDefaulted:     true,
		},
		{
			name:              "cluster scan: whitespace only defaults to default",
			identNamespace:    "   ",
			explicitNamespace: "  ",
			isClusterScan:     true,
			wantNamespace:     "default",
			wantDefaulted:     true,
		},
		{
			name:              "file scan: both omitted leaves namespace empty",
			identNamespace:    "",
			explicitNamespace: "",
			isClusterScan:     false,
			wantNamespace:     "",
			wantDefaulted:     false,
		},
		{
			name:              "file scan: whitespace only leaves namespace empty",
			identNamespace:    "  ",
			explicitNamespace: "   ",
			isClusterScan:     false,
			wantNamespace:     "",
			wantDefaulted:     false,
		},
		{
			name:              "identifier provides namespace",
			identNamespace:    "kube-system",
			explicitNamespace: "",
			isClusterScan:     true,
			wantNamespace:     "kube-system",
			wantDefaulted:     false,
		},
		{
			name:              "file scan: identifier provides namespace",
			identNamespace:    "staging",
			explicitNamespace: "",
			isClusterScan:     false,
			wantNamespace:     "staging",
			wantDefaulted:     false,
		},
		{
			name:              "explicit provides namespace",
			identNamespace:    "",
			explicitNamespace: "staging",
			isClusterScan:     true,
			wantNamespace:     "staging",
			wantDefaulted:     false,
		},
		{
			name:              "both provide same namespace",
			identNamespace:    "prod",
			explicitNamespace: "prod",
			isClusterScan:     true,
			wantNamespace:     "prod",
			wantDefaulted:     false,
		},
		{
			name:              "explicit wildcard resolves to empty cluster-wide",
			identNamespace:    "",
			explicitNamespace: "*",
			isClusterScan:     true,
			wantNamespace:     "",
			wantDefaulted:     false,
		},
		{
			name:              "identifier wildcard resolves to empty cluster-wide",
			identNamespace:    "*",
			explicitNamespace: "",
			isClusterScan:     true,
			wantNamespace:     "",
			wantDefaulted:     false,
		},
		{
			name:              "both provide wildcard",
			identNamespace:    "*",
			explicitNamespace: "*",
			isClusterScan:     true,
			wantNamespace:     "",
			wantDefaulted:     false,
		},
		{
			name:              "conflict between two different namespaces",
			identNamespace:    "staging",
			explicitNamespace: "prod",
			isClusterScan:     true,
			wantErr:           "conflicting namespaces: workload identifier specifies \"staging\" but namespace specifies \"prod\"",
		},
		{
			name:              "conflict between identifier namespace and explicit wildcard",
			identNamespace:    "staging",
			explicitNamespace: "*",
			isClusterScan:     true,
			wantErr:           "conflicting namespaces: workload identifier specifies \"staging\" but namespace specifies \"*\"",
		},
		{
			name:              "conflict between identifier wildcard and explicit namespace",
			identNamespace:    "*",
			explicitNamespace: "prod",
			isClusterScan:     false,
			wantErr:           "conflicting namespaces: workload identifier specifies \"*\" but namespace specifies \"prod\"",
		},
		{
			name:              "error precedence: format error in explicit namespace fires before conflict",
			identNamespace:    "staging",
			explicitNamespace: "Prod!",
			isClusterScan:     true,
			wantErr:           "invalid namespace \"Prod!\"",
		},
		{
			name:              "error precedence: format error in identifier namespace fires before conflict",
			identNamespace:    "Staging!",
			explicitNamespace: "prod",
			isClusterScan:     true,
			wantErr:           "invalid namespace \"Staging!\"",
		},
		{
			name:              "file scan: invalid explicit namespace returns format error",
			identNamespace:    "",
			explicitNamespace: "Invalid_NS!",
			isClusterScan:     false,
			wantErr:           "invalid namespace \"Invalid_NS!\"",
		},
		{
			name:              "file scan: invalid identifier namespace returns format error",
			identNamespace:    "Invalid_NS!",
			explicitNamespace: "",
			isClusterScan:     false,
			wantErr:           "invalid namespace \"Invalid_NS!\"",
		},
		{
			name:              "namespace with dots rejected as RFC 1123 label violation",
			identNamespace:    "ns.with.dots",
			explicitNamespace: "",
			isClusterScan:     true,
			wantErr:           "invalid namespace \"ns.with.dots\"",
		},
		{
			name:              "namespace length boundary 63 chars valid",
			identNamespace:    strings.Repeat("a", 63),
			explicitNamespace: "",
			isClusterScan:     true,
			wantNamespace:     strings.Repeat("a", 63),
			wantDefaulted:     false,
		},
		{
			name:              "namespace length boundary 64 chars invalid",
			identNamespace:    strings.Repeat("a", 64),
			explicitNamespace: "",
			isClusterScan:     true,
			wantErr:           "invalid namespace",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotNamespace, gotDefaulted, err := ResolveWorkloadNamespace(tt.identNamespace, tt.explicitNamespace, tt.isClusterScan)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				assert.False(t, gotDefaulted)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantNamespace, gotNamespace)
			assert.Equal(t, tt.wantDefaulted, gotDefaulted)
		})
	}
}
