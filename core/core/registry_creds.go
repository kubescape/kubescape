package core

import (
	"cmp"
	"context"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/url"
	"path"
	"slices"
	"strings"

	"github.com/distribution/reference"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/pkg/imagescan"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type dockerConfig struct {
	Auths map[string]dockerAuthConfig `json:"auths"`
}

type dockerAuthConfig struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Auth     string `json:"auth"`
}

// pullSecretCache fetches each pull secret from the cluster at most once.
// collectImageScanTargets creates one per scan, so workloads that share a
// pull secret reuse one read and the next scan reads the secrets again. A
// failed read is not cached and is retried on the next lookup. It is not safe
// for concurrent use; collectImageScanTargets visits workloads one at a time.
type pullSecretCache struct {
	k8sApi  *k8sinterface.KubernetesApi
	secrets map[string]*corev1.Secret
}

func newPullSecretCache(k8sApi *k8sinterface.KubernetesApi) *pullSecretCache {
	if k8sApi == nil || k8sApi.KubernetesClient == nil {
		return nil
	}
	return &pullSecretCache{k8sApi: k8sApi, secrets: make(map[string]*corev1.Secret)}
}

func (c *pullSecretCache) get(ctx context.Context, namespace, name string) (*corev1.Secret, error) {
	key := namespace + "/" + name
	if secret, ok := c.secrets[key]; ok {
		return secret, nil
	}
	secret, err := c.k8sApi.KubernetesClient.CoreV1().Secrets(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	c.secrets[key] = secret
	return secret, nil
}

// resolveRegistryCredentials extracts imagePullSecrets from a workload, fetches
// them through the scan's secret cache, and returns every usable credential
// that applies to the image registry. Like the kubelet, which adds all of a
// pod's pull secrets to one keyring and tries every match, it does not stop at
// the first secret with a match; orderRegistryCredentials puts the result in
// the kubelet's order.
func resolveRegistryCredentials(ctx context.Context, secrets *pullSecretCache, wl workloadinterface.IWorkload, image string) []registryCredential {
	if secrets == nil {
		return nil
	}

	imagePullSecrets, err := wl.GetImagePullSecret()
	if err != nil || len(imagePullSecrets) == 0 {
		return nil
	}

	namespace := wl.GetNamespace()
	if namespace == "" {
		namespace = "default"
	}

	ref, err := reference.ParseNormalizedNamed(image)
	if err != nil {
		return nil
	}
	domain, repository := reference.Domain(ref), reference.Path(ref)

	var resolved []registryCredential
	for i, secretRef := range imagePullSecrets {
		secret, err := secrets.get(ctx, namespace, secretRef.Name)
		if err != nil {
			logger.L().Ctx(ctx).Warning("failed to fetch imagePullSecret", helpers.String("secret", secretRef.Name), helpers.String("namespace", namespace), helpers.Error(err))
			continue
		}

		// Like the kubelet (secretsToTrackedDockerConfigs in Kubernetes'
		// pkg/credentialprovider/secrets), read only the key that matches the
		// secret's type, so a credential the pod would not use is never offered.
		var matches []registryCredential
		switch secret.Type {
		case corev1.SecretTypeDockerConfigJson:
			var cfg dockerConfig
			if err := json.Unmarshal(secret.Data[corev1.DockerConfigJsonKey], &cfg); err == nil {
				matches = extractCredsFromAuths(cfg.Auths, domain, repository)
			}
		case corev1.SecretTypeDockercfg:
			var auths map[string]dockerAuthConfig
			if err := json.Unmarshal(secret.Data[corev1.DockerConfigKey], &auths); err == nil {
				matches = extractCredsFromAuths(auths, domain, repository)
			}
		}

		for _, m := range matches {
			m.secret = i
			resolved = append(resolved, m)
		}
	}

	return resolved
}

// registryCredential is a usable credential for an image, with the normalized
// key (host and path) that matched it and the position of its pull secret in
// the workload's imagePullSecrets. Both decide the order the kubelet tries it in.
type registryCredential struct {
	key         string
	secret      int
	credentials imagescan.RegistryCredentials
}

// orderRegistryCredentials returns the credentials in the order the kubelet
// tries them (BasicDockerKeyring in Kubernetes' pkg/credentialprovider): keys
// in reverse lexical order, so a key scoped to a repository path comes before
// the bare host and a literal host before a wildcard one, and credentials for
// the same key in pull secret order. Credentials that are otherwise equal are
// compared field by field, so the result does not depend on the order the
// workloads were visited in. Repeated credentials are kept only at their first
// position.
func orderRegistryCredentials(resolved []registryCredential) []imagescan.RegistryCredentials {
	sorted := slices.Clone(resolved)
	slices.SortFunc(sorted, func(a, b registryCredential) int {
		if c := strings.Compare(b.key, a.key); c != 0 {
			return c
		}
		if c := cmp.Compare(a.secret, b.secret); c != 0 {
			return c
		}
		return cmp.Or(
			strings.Compare(a.credentials.Authority, b.credentials.Authority),
			strings.Compare(a.credentials.Username, b.credentials.Username),
			strings.Compare(a.credentials.Password, b.credentials.Password),
			strings.Compare(a.credentials.Token, b.credentials.Token),
		)
	})

	ordered := make([]imagescan.RegistryCredentials, 0, len(sorted))
	for _, r := range sorted {
		if !slices.Contains(ordered, r.credentials) {
			ordered = append(ordered, r.credentials)
		}
	}
	return ordered
}

// registryKey is a docker config "auths" key, normalized the way the kubelet
// keyring normalizes it (BasicDockerKeyring.Add in Kubernetes'
// pkg/credentialprovider/keyring.go): the scheme is dropped and a leading
// /v1/ or /v2/ API path is ignored. The Docker Hub host aliases also become
// docker.io, the domain reference.Domain reports for Docker Hub images.
type registryKey struct {
	raw  string
	host string
	path string
}

func parseRegistryKey(raw string) (registryKey, bool) {
	key := raw
	if !strings.HasPrefix(key, "http://") && !strings.HasPrefix(key, "https://") {
		key = "https://" + key
	}
	u, err := url.Parse(key)
	if err != nil || u.Host == "" {
		return registryKey{}, false
	}
	host := u.Host
	if host == "registry-1.docker.io" || host == "index.docker.io" {
		host = "docker.io"
	}
	keyPath := u.Path
	if strings.HasPrefix(keyPath, "/v1/") || strings.HasPrefix(keyPath, "/v2/") {
		keyPath = keyPath[3:]
	}
	if keyPath == "/" {
		keyPath = ""
	}
	return registryKey{raw: raw, host: host, path: keyPath}, true
}

// matches reports whether the key applies to an image in repository on the
// registry domain, following URLsMatch in the kubelet keyring: the hosts must
// have the same number of labels, each key label is a glob pattern for the
// matching domain label (so "*.example.com" covers "registry.example.com"),
// the ports must be equal, and the repository path must start with the key's
// path (so "registry.example.com/team" covers "registry.example.com/team/app").
func (k registryKey) matches(domain, repository string) bool {
	keyLabels, keyPort := splitRegistryHost(k.host)
	domainLabels, domainPort := splitRegistryHost(domain)
	if keyPort != domainPort || len(keyLabels) != len(domainLabels) {
		return false
	}
	if !strings.HasPrefix("/"+repository, k.path) {
		return false
	}
	for i, pattern := range keyLabels {
		if matched, err := path.Match(pattern, domainLabels[i]); err != nil || !matched {
			return false
		}
	}
	return true
}

func splitRegistryHost(hostport string) (labels []string, port string) {
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		host, port = hostport, ""
	}
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		// Without a port, SplitHostPort leaves an IPv6 literal bracketed,
		// and path.Match would read the brackets as a character class.
		// The address itself has no glob metacharacters, so as a single
		// label it is compared literally.
		return []string{host[1 : len(host)-1]}, port
	}
	return strings.Split(host, "."), port
}

// extractCredsFromAuths returns the usable credentials among the auths entries
// that apply to an image in repository on the registry domain. Like the
// kubelet, it orders the matching keys in reverse lexical order, so a key
// scoped to a repository path comes before the bare registry host and a
// literal host before a wildcard one. The order is deterministic even when
// several keys match.
func extractCredsFromAuths(auths map[string]dockerAuthConfig, domain, repository string) []registryCredential {
	keys := make([]registryKey, 0, len(auths))
	for raw := range auths {
		if key, ok := parseRegistryKey(raw); ok && key.matches(domain, repository) {
			keys = append(keys, key)
		}
	}
	slices.SortFunc(keys, func(a, b registryKey) int {
		if c := strings.Compare(b.host+b.path, a.host+a.path); c != 0 {
			return c
		}
		return strings.Compare(a.raw, b.raw)
	})

	var matches []registryCredential
	for _, key := range keys {
		auth := auths[key.raw]
		creds := imagescan.RegistryCredentials{
			// The scanner matches credentials to the registry an image is
			// pulled from, so a wildcard key must not become the authority.
			Authority: domain,
			Username:  auth.Username,
			Password:  auth.Password,
		}
		if auth.Auth != "" {
			// auth is base64 encoded username:password. sometimes it's used as token, but actually syft expects username/password if present, or token
			// Let's decode if username and password are empty
			if auth.Username == "" && auth.Password == "" {
				decoded, err := base64.StdEncoding.DecodeString(auth.Auth)
				if err == nil {
					parts := strings.SplitN(string(decoded), ":", 2)
					if len(parts) == 2 {
						creds.Username = parts[0]
						creds.Password = parts[1]
					} else {
						creds.Token = auth.Auth
					}
				} else {
					creds.Token = auth.Auth
				}
			}
		}
		if creds.Token != "" || (creds.Username != "" && creds.Password != "") {
			matches = append(matches, registryCredential{key: key.host + key.path, credentials: creds})
		}
	}
	return matches
}
