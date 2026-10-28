package core

import (
	"context"
	"encoding/base64"
	"testing"

	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/pkg/imagescan"
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
			}, "registry.example.com", "team/app")

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
			}, "registry.example.com", "team/app")

			require.True(t, found)
			assert.Equal(t, imagescan.RegistryCredentials{
				Authority: "registry.example.com",
				Username:  "user",
				Password:  "password",
			}, creds)
		})
	}
}

func TestExtractCredsFromAuthsFollowsKubeletKeyMatching(t *testing.T) {
	basic := func(user string) dockerAuthConfig {
		return dockerAuthConfig{Username: user, Password: "password"}
	}
	tests := []struct {
		name         string
		auths        map[string]dockerAuthConfig
		domain       string
		repository   string
		expectedUser string
	}{
		{
			name:         "wildcard host label",
			auths:        map[string]dockerAuthConfig{"*.example.com": basic("wildcard")},
			domain:       "registry.example.com",
			repository:   "team/app",
			expectedUser: "wildcard",
		},
		{
			name:       "wildcard host label does not span labels",
			auths:      map[string]dockerAuthConfig{"*.example.com": basic("wildcard")},
			domain:     "eu.registry.example.com",
			repository: "team/app",
		},
		{
			name:         "literal host is tried before a wildcard host",
			auths:        map[string]dockerAuthConfig{"*.example.com": basic("wildcard"), "registry.example.com": basic("literal")},
			domain:       "registry.example.com",
			repository:   "team/app",
			expectedUser: "literal",
		},
		{
			name:         "path-scoped key applies to repositories under its path",
			auths:        map[string]dockerAuthConfig{"registry.example.com/team-a": basic("team-a"), "registry.example.com/team-b": basic("team-b")},
			domain:       "registry.example.com",
			repository:   "team-b/app",
			expectedUser: "team-b",
		},
		{
			name:       "path-scoped key does not apply to other repositories",
			auths:      map[string]dockerAuthConfig{"registry.example.com/team-a": basic("team-a")},
			domain:     "registry.example.com",
			repository: "team-b/app",
		},
		{
			name:         "path-scoped key is tried before the bare host",
			auths:        map[string]dockerAuthConfig{"registry.example.com": basic("host"), "https://registry.example.com/team": basic("team")},
			domain:       "registry.example.com",
			repository:   "team/app",
			expectedUser: "team",
		},
		{
			name:         "bare host applies outside a path-scoped key",
			auths:        map[string]dockerAuthConfig{"registry.example.com": basic("host"), "registry.example.com/team": basic("team")},
			domain:       "registry.example.com",
			repository:   "other/app",
			expectedUser: "host",
		},
		{
			name:         "a less specific key is used when the more specific one is unusable",
			auths:        map[string]dockerAuthConfig{"registry.example.com": basic("host"), "registry.example.com/team": {}},
			domain:       "registry.example.com",
			repository:   "team/app",
			expectedUser: "host",
		},
		{
			name:         "registry API version path is ignored",
			auths:        map[string]dockerAuthConfig{"https://registry.example.com/v2/": basic("api")},
			domain:       "registry.example.com",
			repository:   "team/app",
			expectedUser: "api",
		},
		{
			name:         "Docker Hub index key",
			auths:        map[string]dockerAuthConfig{"https://index.docker.io/v1/": basic("hub")},
			domain:       "docker.io",
			repository:   "library/nginx",
			expectedUser: "hub",
		},
		{
			name:         "matching port",
			auths:        map[string]dockerAuthConfig{"registry.example.com:5000": basic("port")},
			domain:       "registry.example.com:5000",
			repository:   "team/app",
			expectedUser: "port",
		},
		{
			name:       "port mismatch",
			auths:      map[string]dockerAuthConfig{"registry.example.com:5000": basic("port")},
			domain:     "registry.example.com",
			repository: "team/app",
		},
		{
			name:         "IPv6 registry without a port",
			auths:        map[string]dockerAuthConfig{"[2001:db8::1]": basic("ipv6")},
			domain:       "[2001:db8::1]",
			repository:   "team/app",
			expectedUser: "ipv6",
		},
		{
			name:         "IPv6 registry with a port",
			auths:        map[string]dockerAuthConfig{"https://[2001:db8::1]:5000": basic("ipv6")},
			domain:       "[2001:db8::1]:5000",
			repository:   "team/app",
			expectedUser: "ipv6",
		},
		{
			name:       "different IPv6 registry",
			auths:      map[string]dockerAuthConfig{"[2001:db8::2]": basic("ipv6")},
			domain:     "[2001:db8::1]",
			repository: "team/app",
		},
		{
			name:       "IPv6 registry port mismatch",
			auths:      map[string]dockerAuthConfig{"[2001:db8::1]:5000": basic("ipv6")},
			domain:     "[2001:db8::1]",
			repository: "team/app",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Map iteration order varies between runs; the selected
			// credentials must not.
			for range 20 {
				creds, found := extractCredsFromAuths(tt.auths, tt.domain, tt.repository)
				if tt.expectedUser == "" {
					require.False(t, found)
					require.Equal(t, imagescan.RegistryCredentials{}, creds)
					continue
				}
				require.True(t, found)
				require.Equal(t, imagescan.RegistryCredentials{
					Authority: tt.domain,
					Username:  tt.expectedUser,
					Password:  "password",
				}, creds)
			}
		})
	}
}

func TestResolveRegistryCredentialsMatchesWildcardKey(t *testing.T) {
	const namespace = "default"
	client := fake.NewClientset(&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "registry-auth", Namespace: namespace},
		Type:       corev1.SecretTypeDockerConfigJson,
		Data: map[string][]byte{
			corev1.DockerConfigJsonKey: []byte(`{"auths":{"*.example.com":{"username":"user","password":"password"}}}`),
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
			"imagePullSecrets": []interface{}{
				map[string]interface{}{"name": "registry-auth"},
			},
		},
	})

	creds, found := resolveRegistryCredentials(context.Background(), k8sAPI, workload, "registry.example.com/team/app:tag")

	require.True(t, found)
	assert.Equal(t, imagescan.RegistryCredentials{
		Authority: "registry.example.com",
		Username:  "user",
		Password:  "password",
	}, creds)
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
