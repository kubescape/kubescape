package core

import (
	"context"
	"encoding/base64"
	"testing"

	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/pkg/imagescan"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestExtractCredsFromAuthsRejectsUnusableCredentials(t *testing.T) {
	tests := []struct {
		name string
		auth dockerAuthConfig
	}{
		{
			name: "empty registry entry",
		},
		{
			name: "username without password",
			auth: dockerAuthConfig{Username: "user"},
		},
		{
			name: "password without username",
			auth: dockerAuthConfig{Password: "password"},
		},
		{
			name: "encoded empty username and password",
			auth: dockerAuthConfig{Auth: base64.StdEncoding.EncodeToString([]byte(":"))},
		},
		{
			name: "encoded username without password",
			auth: dockerAuthConfig{Auth: base64.StdEncoding.EncodeToString([]byte("user:"))},
		},
		{
			name: "encoded password without username",
			auth: dockerAuthConfig{Auth: base64.StdEncoding.EncodeToString([]byte(":password"))},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			creds, found := extractCredsFromAuths(map[string]dockerAuthConfig{
				"registry.example.com": tt.auth,
			}, "registry.example.com")

			assert.False(t, found)
			assert.Equal(t, imagescan.RegistryCredentials{}, creds)
		})
	}
}

func TestExtractCredsFromAuthsPreservesBasicAuth(t *testing.T) {
	tests := []struct {
		name string
		auth dockerAuthConfig
	}{
		{
			name: "explicit username and password",
			auth: dockerAuthConfig{Username: "user", Password: "password"},
		},
		{
			name: "base64 encoded username and password",
			auth: dockerAuthConfig{Auth: base64.StdEncoding.EncodeToString([]byte("user:password"))},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			creds, found := extractCredsFromAuths(map[string]dockerAuthConfig{
				"registry.example.com": tt.auth,
			}, "registry.example.com")

			require.True(t, found)
			assert.Equal(t, imagescan.RegistryCredentials{
				Authority: "registry.example.com",
				Username:  "user",
				Password:  "password",
			}, creds)
		})
	}
}

func TestResolveRegistryCredentialsSkipsUnusableSecrets(t *testing.T) {
	const namespace = "default"
	tests := []struct {
		name              string
		imagePullSecrets  []interface{}
		expected          imagescan.RegistryCredentials
		expectedToBeFound bool
	}{
		{
			name: "selects a later usable secret",
			imagePullSecrets: []interface{}{
				map[string]interface{}{"name": "empty-auth"},
				map[string]interface{}{"name": "valid-auth"},
			},
			expected: imagescan.RegistryCredentials{
				Authority: "registry.example.com",
				Username:  "user",
				Password:  "password",
			},
			expectedToBeFound: true,
		},
		{
			name: "reports no credentials when all secrets are unusable",
			imagePullSecrets: []interface{}{
				map[string]interface{}{"name": "empty-auth"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := fake.NewClientset(
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{Name: "empty-auth", Namespace: namespace},
					Type:       corev1.SecretTypeDockerConfigJson,
					Data: map[string][]byte{
						corev1.DockerConfigJsonKey: []byte(`{"auths":{"registry.example.com":{}}}`),
					},
				},
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{Name: "valid-auth", Namespace: namespace},
					Type:       corev1.SecretTypeDockerConfigJson,
					Data: map[string][]byte{
						corev1.DockerConfigJsonKey: []byte(`{"auths":{"registry.example.com":{"username":"user","password":"password"}}}`),
					},
				},
			)
			k8sAPI := &k8sinterface.KubernetesApi{KubernetesClient: client}
			workload := workloadinterface.NewWorkloadObj(map[string]interface{}{
				"apiVersion": "v1",
				"kind":       "Pod",
				"metadata": map[string]interface{}{
					"name":      "app",
					"namespace": namespace,
				},
				"spec": map[string]interface{}{
					"imagePullSecrets": tt.imagePullSecrets,
				},
			})

			creds, found := resolveRegistryCredentials(
				context.Background(),
				k8sAPI,
				workload,
				"registry.example.com/team/app:tag",
			)

			assert.Equal(t, tt.expectedToBeFound, found)
			assert.Equal(t, tt.expected, creds)
		})
	}
}

func TestCollectImageScanTargetsScopesPullSecretsToLiveCluster(t *testing.T) {
	const (
		namespace  = "default"
		secretName = "registry-auth"
		image      = "registry.example.com/team/app:tag"
	)

	tests := []struct {
		name              string
		scanType          cautils.ScanTypes
		scanningContext   cautils.ScanningContext
		singleResource    bool
		expectSecretRead  bool
		expectCredentials bool
	}{
		{
			name:            "single file repository scan",
			scanType:        cautils.ScanTypeRepo,
			scanningContext: cautils.ContextFile,
		},
		{
			name:            "directory repository scan",
			scanType:        cautils.ScanTypeRepo,
			scanningContext: cautils.ContextDir,
		},
		{
			name:            "local Git repository scan",
			scanType:        cautils.ScanTypeRepo,
			scanningContext: cautils.ContextGitLocal,
		},
		{
			name:            "remote Git repository scan",
			scanType:        cautils.ScanTypeRepo,
			scanningContext: cautils.ContextGitRemote,
		},
		{
			name:            "file workload scan",
			scanType:        cautils.ScanTypeWorkload,
			scanningContext: cautils.ContextFile,
			singleResource:  true,
		},
		{
			name:            "directory workload scan",
			scanType:        cautils.ScanTypeWorkload,
			scanningContext: cautils.ContextDir,
			singleResource:  true,
		},
		{
			name:              "live cluster scan",
			scanType:          cautils.ScanTypeCluster,
			scanningContext:   cautils.ContextCluster,
			expectSecretRead:  true,
			expectCredentials: true,
		},
		{
			name:              "live cluster workload scan",
			scanType:          cautils.ScanTypeWorkload,
			scanningContext:   cautils.ContextCluster,
			singleResource:    true,
			expectSecretRead:  true,
			expectCredentials: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := fake.NewClientset(&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: secretName, Namespace: namespace},
				Type:       corev1.SecretTypeDockerConfigJson,
				Data: map[string][]byte{
					corev1.DockerConfigJsonKey: []byte(`{"auths":{"registry.example.com":{"username":"user","password":"password"}}}`),
				},
			})
			k8sAPI := &k8sinterface.KubernetesApi{KubernetesClient: client}
			workload := workloadinterface.NewWorkloadObj(map[string]interface{}{
				"apiVersion": "v1",
				"kind":       "Pod",
				"metadata": map[string]interface{}{
					"name":      "app",
					"namespace": namespace,
				},
				"spec": map[string]interface{}{
					"containers": []interface{}{
						map[string]interface{}{"name": "app", "image": image},
					},
					"imagePullSecrets": []interface{}{
						map[string]interface{}{"name": secretName},
					},
				},
			})
			scanData := cautils.NewOPASessionObjMock()
			if tt.singleResource {
				scanData.SingleResourceScan = workload
			} else {
				scanData.AllResources[workload.GetID()] = workload
			}

			images, credentials, containerErrors := collectImageScanTargets(
				tt.scanType,
				scanData,
				context.Background(),
				tt.scanningContext,
				k8sAPI,
				"",
			)

			assert.Empty(t, containerErrors)
			assert.True(t, images.Contains(ImageScanTarget{Image: image}))
			if tt.expectSecretRead {
				require.Len(t, client.Actions(), 1)
				assert.Equal(t, "get", client.Actions()[0].GetVerb())
				assert.Equal(t, "secrets", client.Actions()[0].GetResource().Resource)
			} else {
				assert.Empty(t, client.Actions(), "offline image scans must not read imagePullSecrets from the current cluster")
			}

			if tt.expectCredentials {
				require.Len(t, credentials[image], 1)
				assert.Equal(t, imagescan.RegistryCredentials{
					Authority: "registry.example.com",
					Username:  "user",
					Password:  "password",
				}, credentials[image][0])
			} else {
				assert.NotContains(t, credentials, image)
			}
		})
	}
}
