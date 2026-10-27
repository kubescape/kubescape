package core

import (
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

// resolveRegistryCredentials extracts imagePullSecrets from a workload, fetches them from the cluster,
// and resolves the credentials for the given image registry.
func resolveRegistryCredentials(ctx context.Context, k8sApi *k8sinterface.KubernetesApi, wl workloadinterface.IWorkload, image string) (imagescan.RegistryCredentials, bool) {
	if k8sApi == nil || k8sApi.KubernetesClient == nil {
		return imagescan.RegistryCredentials{}, false
	}

	imagePullSecrets, err := wl.GetImagePullSecret()
	if err != nil || len(imagePullSecrets) == 0 {
		return imagescan.RegistryCredentials{}, false
	}

	namespace := wl.GetNamespace()
	if namespace == "" {
		namespace = "default"
	}

	ref, err := reference.ParseNormalizedNamed(image)
	if err != nil {
		return imagescan.RegistryCredentials{}, false
	}
	domain, repository := reference.Domain(ref), reference.Path(ref)

	for _, secretRef := range imagePullSecrets {
		secret, err := k8sApi.KubernetesClient.CoreV1().Secrets(namespace).Get(ctx, secretRef.Name, metav1.GetOptions{})
		if err != nil {
			logger.L().Ctx(ctx).Warning("failed to fetch imagePullSecret", helpers.String("secret", secretRef.Name), helpers.String("namespace", namespace), helpers.Error(err))
			continue
		}

		// Try parsing .dockerconfigjson
		if dockerConfigJSON, ok := secret.Data[".dockerconfigjson"]; ok {
			var cfg dockerConfig
			if err := json.Unmarshal(dockerConfigJSON, &cfg); err == nil {
				if creds, found := extractCredsFromAuths(cfg.Auths, domain, repository); found {
					return creds, true
				}
			}
		}

		// Try parsing .dockercfg
		if dockerCfg, ok := secret.Data[".dockercfg"]; ok {
			var auths map[string]dockerAuthConfig
			if err := json.Unmarshal(dockerCfg, &auths); err == nil {
				if creds, found := extractCredsFromAuths(auths, domain, repository); found {
					return creds, true
				}
			}
		}
	}

	return imagescan.RegistryCredentials{}, false
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
	return strings.Split(host, "."), port
}

// extractCredsFromAuths returns the first usable credentials among the auths
// entries that apply to an image in repository on the registry domain. Like
// the kubelet, it tries the matching keys in reverse lexical order, so a key
// scoped to a repository path is tried before the bare registry host and a
// literal host before a wildcard one. The order is deterministic even when
// several keys match.
func extractCredsFromAuths(auths map[string]dockerAuthConfig, domain, repository string) (imagescan.RegistryCredentials, bool) {
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
			return creds, true
		}
	}
	return imagescan.RegistryCredentials{}, false
}
