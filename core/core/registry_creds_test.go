package core

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"

	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/pkg/imagescan"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
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
			matches := extractCredsFromAuths(map[string]dockerAuthConfig{
				"registry.example.com": tt.auth,
			}, "registry.example.com", "team/app")

			assert.Empty(t, matches)
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
			matches := extractCredsFromAuths(map[string]dockerAuthConfig{
				"registry.example.com": tt.auth,
			}, "registry.example.com", "team/app")

			require.Len(t, matches, 1)
			assert.Equal(t, imagescan.RegistryCredentials{
				Authority: "registry.example.com",
				Username:  "user",
				Password:  "password",
			}, matches[0].credentials)
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
				matches := extractCredsFromAuths(tt.auths, tt.domain, tt.repository)
				if tt.expectedUser == "" {
					require.Empty(t, matches)
					continue
				}
				require.NotEmpty(t, matches)
				require.Equal(t, imagescan.RegistryCredentials{
					Authority: tt.domain,
					Username:  tt.expectedUser,
					Password:  "password",
				}, matches[0].credentials)
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

	resolved := resolveRegistryCredentials(context.Background(), newPullSecretCache(k8sAPI), workload, "registry.example.com/team/app:tag")

	require.Len(t, resolved, 1)
	assert.Equal(t, imagescan.RegistryCredentials{
		Authority: "registry.example.com",
		Username:  "user",
		Password:  "password",
	}, resolved[0].credentials)
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

			resolved := resolveRegistryCredentials(
				context.Background(),
				newPullSecretCache(k8sAPI),
				workload,
				"registry.example.com/team/app:tag",
			)

			if !tt.expectedToBeFound {
				assert.Empty(t, resolved)
				return
			}
			require.Len(t, resolved, 1)
			assert.Equal(t, tt.expected, resolved[0].credentials)
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

// registryAuth is one docker config "auths" entry for the pull-secret tests.
// The password is always containerTypesPlaceholderPassword, which is not a
// real secret; an empty username makes the entry unusable.
type registryAuth struct {
	key      string
	username string
}

func dockerAuths(t *testing.T, entries ...registryAuth) []byte {
	t.Helper()
	auths := make(map[string]dockerAuthConfig, len(entries))
	for _, e := range entries {
		auth := dockerAuthConfig{}
		if e.username != "" {
			auth = dockerAuthConfig{Username: e.username, Password: containerTypesPlaceholderPassword}
		}
		auths[e.key] = auth
	}
	encoded, err := json.Marshal(auths)
	require.NoError(t, err)
	return encoded
}

func pullSecretObject(name, namespace string, secretType corev1.SecretType, data map[string][]byte) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Type:       secretType,
		Data:       data,
	}
}

func dockerConfigJSON(t *testing.T, entries ...registryAuth) []byte {
	t.Helper()
	config, err := json.Marshal(map[string]json.RawMessage{"auths": dockerAuths(t, entries...)})
	require.NoError(t, err)
	return config
}

func dockerConfigSecret(t *testing.T, name string, entries ...registryAuth) runtime.Object {
	t.Helper()
	return pullSecretObject(name, "default", corev1.SecretTypeDockerConfigJson, map[string][]byte{corev1.DockerConfigJsonKey: dockerConfigJSON(t, entries...)})
}

func podPullingImage(name, namespace, image string, pullSecrets ...string) workloadinterface.IMetadata {
	refs := make([]interface{}, 0, len(pullSecrets))
	for _, secret := range pullSecrets {
		refs = append(refs, map[string]interface{}{"name": secret})
	}
	spec := map[string]interface{}{
		"containers": []interface{}{map[string]interface{}{"name": "app", "image": image}},
	}
	if len(refs) > 0 {
		spec["imagePullSecrets"] = refs
	}
	return workloadinterface.NewWorkloadObj(map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata":   map[string]interface{}{"name": name, "namespace": namespace},
		"spec":       spec,
	})
}

func registryUsers(creds []imagescan.RegistryCredentials) []string {
	users := make([]string, 0, len(creds))
	for _, c := range creds {
		users = append(users, c.Username)
	}
	return users
}

func collectPullSecretCredentials(t *testing.T, k8sAPI *k8sinterface.KubernetesApi, workloads ...workloadinterface.IMetadata) map[string][]imagescan.RegistryCredentials {
	t.Helper()
	scanData := cautils.NewOPASessionObjMock()
	for _, workload := range workloads {
		scanData.AllResources[workload.GetID()] = workload
	}
	_, credentials, containerErrors := collectImageScanTargets(
		cautils.ScanTypeCluster, scanData, context.Background(), cautils.ContextCluster, k8sAPI, "")
	require.Empty(t, containerErrors)
	return credentials
}

const pullSecretTestImage = "registry.example.com/team-a/app:1.0"

// Like the kubelet, which adds all of a pod's pull secrets to one keyring,
// every usable credential that matches the image is offered to the scan,
// most specific key first.
func TestCollectImageScanTargetsOffersEveryPullSecretCredential(t *testing.T) {
	tests := []struct {
		name        string
		secrets     []runtime.Object
		pullSecrets []string
		wantUsers   []string
	}{
		{
			name: "a path-scoped key in a later pull secret comes first",
			secrets: []runtime.Object{
				dockerConfigSecret(t, "org-pull", registryAuth{"registry.example.com", "org"}),
				dockerConfigSecret(t, "team-a-pull", registryAuth{"registry.example.com/team-a", "team"}),
			},
			pullSecrets: []string{"org-pull", "team-a-pull"},
			wantUsers:   []string{"team", "org"},
		},
		{
			name: "a stale path-scoped key does not hide the bare host in the same secret",
			secrets: []runtime.Object{
				dockerConfigSecret(t, "pull",
					registryAuth{"registry.example.com/team-a", "stale"},
					registryAuth{"registry.example.com", "org"}),
			},
			pullSecrets: []string{"pull"},
			wantUsers:   []string{"stale", "org"},
		},
		{
			name: "the same key in two pull secrets keeps pull secret order",
			secrets: []runtime.Object{
				dockerConfigSecret(t, "first-pull", registryAuth{"registry.example.com", "zeta"}),
				dockerConfigSecret(t, "second-pull", registryAuth{"registry.example.com", "alpha"}),
			},
			pullSecrets: []string{"first-pull", "second-pull"},
			wantUsers:   []string{"zeta", "alpha"},
		},
		{
			name: "repeated credentials are offered once",
			secrets: []runtime.Object{
				dockerConfigSecret(t, "org-pull", registryAuth{"registry.example.com", "team"}),
				dockerConfigSecret(t, "team-a-pull", registryAuth{"registry.example.com/team-a", "team"}),
			},
			pullSecrets: []string{"org-pull", "team-a-pull"},
			wantUsers:   []string{"team"},
		},
		{
			name: "unusable and unrelated entries are skipped",
			secrets: []runtime.Object{
				dockerConfigSecret(t, "pull",
					registryAuth{"registry.example.com", ""},
					registryAuth{"other.example.com", "other"},
					registryAuth{"registry.example.com/team-a", "team"}),
			},
			pullSecrets: []string{"pull"},
			wantUsers:   []string{"team"},
		},
		{
			name: "a workload without pull secrets resolves no credentials",
			secrets: []runtime.Object{
				dockerConfigSecret(t, "org-pull", registryAuth{"registry.example.com", "org"}),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k8sAPI := &k8sinterface.KubernetesApi{KubernetesClient: fake.NewClientset(tt.secrets...)}
			// Map iteration order varies between runs; the offered order must not.
			for range 20 {
				credentials := collectPullSecretCredentials(t, k8sAPI, podPullingImage("app", "default", pullSecretTestImage, tt.pullSecrets...))
				if tt.wantUsers == nil {
					require.NotContains(t, credentials, pullSecretTestImage)
					continue
				}
				require.Equal(t, tt.wantUsers, registryUsers(credentials[pullSecretTestImage]))
			}
		})
	}
}

// Workloads are visited in map order, so credentials for an image shared by
// several workloads must be ordered after all of them have been collected.
func TestCollectImageScanTargetsOrdersCredentialsAcrossWorkloads(t *testing.T) {
	k8sAPI := &k8sinterface.KubernetesApi{KubernetesClient: fake.NewClientset(
		dockerConfigSecret(t, "org-pull", registryAuth{"registry.example.com", "org"}),
		dockerConfigSecret(t, "team-a-pull", registryAuth{"registry.example.com/team-a", "team"}),
	)}

	for range 20 {
		credentials := collectPullSecretCredentials(t, k8sAPI,
			podPullingImage("org-app", "default", pullSecretTestImage, "org-pull"),
			podPullingImage("team-app", "default", pullSecretTestImage, "team-a-pull"),
		)
		require.Equal(t, []string{"team", "org"}, registryUsers(credentials[pullSecretTestImage]))
	}
}

// Like the kubelet, a pull secret is read in the format its type declares;
// a key in the other format is ignored.
func TestCollectImageScanTargetsReadsPullSecretsByType(t *testing.T) {
	dockercfg := func(entries ...registryAuth) []byte { return dockerAuths(t, entries...) }
	dockerconfigjson := func(entries ...registryAuth) []byte { return dockerConfigJSON(t, entries...) }

	tests := []struct {
		name      string
		secret    *corev1.Secret
		wantUsers []string
	}{
		{
			name: "a dockerconfigjson secret ignores a .dockercfg key",
			secret: pullSecretObject("pull", "default", corev1.SecretTypeDockerConfigJson, map[string][]byte{
				corev1.DockerConfigJsonKey: dockerconfigjson(registryAuth{"registry.example.com/team-a", "json"}),
				corev1.DockerConfigKey:     dockercfg(registryAuth{"registry.example.com", "cfg"}),
			}),
			wantUsers: []string{"json"},
		},
		{
			name: "a dockercfg secret reads .dockercfg",
			secret: pullSecretObject("pull", "default", corev1.SecretTypeDockercfg, map[string][]byte{
				corev1.DockerConfigKey: dockercfg(registryAuth{"registry.example.com", "cfg"}),
			}),
			wantUsers: []string{"cfg"},
		},
		{
			name: "a dockercfg secret ignores a .dockerconfigjson key",
			secret: pullSecretObject("pull", "default", corev1.SecretTypeDockercfg, map[string][]byte{
				corev1.DockerConfigKey:     dockercfg(registryAuth{"registry.example.com", "cfg"}),
				corev1.DockerConfigJsonKey: dockerconfigjson(registryAuth{"registry.example.com/team-a", "json"}),
			}),
			wantUsers: []string{"cfg"},
		},
		{
			name: "a valid key is read next to an invalid one of the other format",
			secret: pullSecretObject("pull", "default", corev1.SecretTypeDockercfg, map[string][]byte{
				corev1.DockerConfigKey:     dockercfg(registryAuth{"registry.example.com", "cfg"}),
				corev1.DockerConfigJsonKey: []byte("not json"),
			}),
			wantUsers: []string{"cfg"},
		},
		{
			name: "an Opaque secret is not a pull secret",
			secret: pullSecretObject("pull", "default", corev1.SecretTypeOpaque, map[string][]byte{
				corev1.DockerConfigJsonKey: dockerconfigjson(registryAuth{"registry.example.com", "json"}),
			}),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k8sAPI := &k8sinterface.KubernetesApi{KubernetesClient: fake.NewClientset(tt.secret)}
			credentials := collectPullSecretCredentials(t, k8sAPI, podPullingImage("app", "default", pullSecretTestImage, "pull"))
			if tt.wantUsers == nil {
				assert.NotContains(t, credentials, pullSecretTestImage)
				return
			}
			assert.Equal(t, tt.wantUsers, registryUsers(credentials[pullSecretTestImage]))
			for _, c := range credentials[pullSecretTestImage] {
				assert.Equal(t, containerTypesPlaceholderPassword, c.Password)
			}
		})
	}
}

func secretGets(client *fake.Clientset) int {
	gets := 0
	for _, action := range client.Actions() {
		if action.GetVerb() == "get" && action.GetResource().Resource == "secrets" {
			gets++
		}
	}
	return gets
}

// Within one scan each pull secret is read once, however many workloads and
// images reference it; the next scan reads it again.
func TestCollectImageScanTargetsReadsEachPullSecretOncePerScan(t *testing.T) {
	const otherImage = "registry.example.com/team-a/worker:1.0"
	client := fake.NewClientset(
		dockerConfigSecret(t, "org-pull", registryAuth{"registry.example.com", "org"}),
		dockerConfigSecret(t, "team-a-pull", registryAuth{"registry.example.com/team-a", "team"}),
	)
	k8sAPI := &k8sinterface.KubernetesApi{KubernetesClient: client}
	twoImages := workloadinterface.NewWorkloadObj(map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata":   map[string]interface{}{"name": "two-images", "namespace": "default"},
		"spec": map[string]interface{}{
			"containers": []interface{}{
				map[string]interface{}{"name": "app", "image": pullSecretTestImage},
				map[string]interface{}{"name": "worker", "image": otherImage},
			},
			"imagePullSecrets": []interface{}{
				map[string]interface{}{"name": "org-pull"},
				map[string]interface{}{"name": "team-a-pull"},
			},
		},
	})
	workloads := []workloadinterface.IMetadata{
		twoImages,
		podPullingImage("app", "default", pullSecretTestImage, "org-pull", "team-a-pull"),
		podPullingImage("org-app", "default", otherImage, "org-pull"),
	}

	credentials := collectPullSecretCredentials(t, k8sAPI, workloads...)
	assert.Equal(t, 2, secretGets(client), "each pull secret is read once per scan")
	assert.Equal(t, []string{"team", "org"}, registryUsers(credentials[pullSecretTestImage]))
	assert.Equal(t, []string{"team", "org"}, registryUsers(credentials[otherImage]))

	updated := dockerConfigSecret(t, "team-a-pull", registryAuth{"registry.example.com/team-a", "rotated"}).(*corev1.Secret)
	_, err := client.CoreV1().Secrets("default").Update(context.Background(), updated, metav1.UpdateOptions{})
	require.NoError(t, err)
	client.ClearActions()

	credentials = collectPullSecretCredentials(t, k8sAPI, workloads...)
	assert.Equal(t, 2, secretGets(client), "a new scan reads the pull secrets again")
	assert.Equal(t, []string{"rotated", "org"}, registryUsers(credentials[pullSecretTestImage]),
		"a new scan sees the updated pull secret")
}

// Pull secrets are namespaced: a secret name in one namespace says nothing
// about a secret with the same name in another, so a workload only gets the
// credentials of its own namespace's secret.
func TestCollectImageScanTargetsKeepsPullSecretsPerNamespace(t *testing.T) {
	const (
		teamAImage = "registry.example.com/team-a/app:1.0"
		teamBImage = "registry.example.com/team-b/app:1.0"
	)
	pullSecret := func(namespace, username string) runtime.Object {
		return pullSecretObject("regcred", namespace, corev1.SecretTypeDockerConfigJson, map[string][]byte{
			corev1.DockerConfigJsonKey: dockerConfigJSON(t, registryAuth{"registry.example.com", username}),
		})
	}
	k8sAPI := &k8sinterface.KubernetesApi{KubernetesClient: fake.NewClientset(
		pullSecret("team-a", "team-a-user"),
		pullSecret("team-b", "team-b-user"),
	)}

	// Map iteration order varies between runs, so either namespace may be
	// read first; both orders must keep the credentials apart.
	for range 20 {
		credentials := collectPullSecretCredentials(t, k8sAPI,
			podPullingImage("app", "team-a", teamAImage, "regcred"),
			podPullingImage("app", "team-b", teamBImage, "regcred"),
		)
		require.Equal(t, []string{"team-a-user"}, registryUsers(credentials[teamAImage]))
		require.Equal(t, []string{"team-b-user"}, registryUsers(credentials[teamBImage]))
	}
}

// A failed read is not cached, so a later lookup in the same scan tries again.
func TestPullSecretCacheRetriesFailedReads(t *testing.T) {
	client := fake.NewClientset()
	cache := newPullSecretCache(&k8sinterface.KubernetesApi{KubernetesClient: client})

	_, err := cache.get(context.Background(), "default", "team-a-pull")
	require.Error(t, err)

	_, err = client.CoreV1().Secrets("default").Create(context.Background(),
		dockerConfigSecret(t, "team-a-pull", registryAuth{"registry.example.com/team-a", "team"}).(*corev1.Secret), metav1.CreateOptions{})
	require.NoError(t, err)

	secret, err := cache.get(context.Background(), "default", "team-a-pull")
	require.NoError(t, err)
	assert.Equal(t, "team-a-pull", secret.Name)
	assert.Nil(t, newPullSecretCache(nil), "no cluster, no pull secret reads")
}

// acceptingImageScanService stands in for a registry that accepts a single
// username and records the credentials each scan attempt used.
type acceptingImageScanService struct {
	username string
	attempts []string
}

func (s *acceptingImageScanService) Scan(_ context.Context, image string, credentials imagescan.RegistryCredentials, _, _ []string) (*cautils.ImageScanData, error) {
	s.attempts = append(s.attempts, credentials.Username)
	if credentials.Username != s.username {
		return nil, errors.New("UNAUTHORIZED: authentication required")
	}
	return &cautils.ImageScanData{Image: image}, nil
}

// The scan retries every offered credential, so an image can be scanned with
// any credential the pod's pull secrets hold for it, as the kubelet can pull it.
func TestImageScanTriesEveryPullSecretCredential(t *testing.T) {
	tests := []struct {
		name         string
		secrets      []runtime.Object
		pullSecrets  []string
		registryUser string
		wantAttempts []string
	}{
		{
			name: "credentials from a later pull secret are tried",
			secrets: []runtime.Object{
				dockerConfigSecret(t, "org-pull", registryAuth{"registry.example.com", "org"}),
				dockerConfigSecret(t, "team-a-pull", registryAuth{"registry.example.com/team-a", "team"}),
			},
			pullSecrets:  []string{"org-pull", "team-a-pull"},
			registryUser: "team",
			wantAttempts: []string{"team"},
		},
		{
			name: "a rejected path-scoped credential falls back to the bare host",
			secrets: []runtime.Object{
				dockerConfigSecret(t, "pull",
					registryAuth{"registry.example.com/team-a", "stale"},
					registryAuth{"registry.example.com", "org"}),
			},
			pullSecrets:  []string{"pull"},
			registryUser: "org",
			wantAttempts: []string{"stale", "org"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k8sAPI := &k8sinterface.KubernetesApi{KubernetesClient: fake.NewClientset(tt.secrets...)}
			scanData := cautils.NewOPASessionObjMock()
			workload := podPullingImage("app", "default", pullSecretTestImage, tt.pullSecrets...)
			scanData.AllResources[workload.GetID()] = workload

			targets, credentials, containerErrors := collectImageScanTargets(
				cautils.ScanTypeCluster, scanData, context.Background(), cautils.ContextCluster, k8sAPI, "")
			require.Empty(t, containerErrors)
			jobs := buildWorkloadImageScanJobs(targets, credentials, imagescan.RegistryCredentials{}, nil)
			require.Len(t, jobs, 1)

			svc := &acceptingImageScanService{username: tt.registryUser}
			scanResult, err := scanWithRegistryMapping(context.Background(), svc, jobs[0].Image, jobs[0].RegistryCredentials, nil, nil, nil, "")

			require.NoError(t, err)
			assert.Equal(t, pullSecretTestImage, scanResult.Image)
			assert.Equal(t, tt.wantAttempts, svc.attempts)
		})
	}
}
