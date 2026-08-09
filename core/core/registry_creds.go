package core

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strings"

	"github.com/distribution/reference"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v3/pkg/imagescan"
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
	domain := reference.Domain(ref)

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
				if creds, found := extractCredsFromAuths(cfg.Auths, domain); found {
					return creds, true
				}
			}
		}

		// Try parsing .dockercfg
		if dockerCfg, ok := secret.Data[".dockercfg"]; ok {
			var auths map[string]dockerAuthConfig
			if err := json.Unmarshal(dockerCfg, &auths); err == nil {
				if creds, found := extractCredsFromAuths(auths, domain); found {
					return creds, true
				}
			}
		}
	}

	return imagescan.RegistryCredentials{}, false
}

func normalizeRegistry(registry string) string {
	if !strings.HasPrefix(registry, "http://") && !strings.HasPrefix(registry, "https://") {
		registry = "https://" + registry
	}
	u, err := url.Parse(registry)
	if err != nil {
		return ""
	}
	host := u.Host
	if host == "registry-1.docker.io" || host == "index.docker.io" {
		host = "docker.io"
	}
	return host
}

func extractCredsFromAuths(auths map[string]dockerAuthConfig, domain string) (imagescan.RegistryCredentials, bool) {
	for registry, auth := range auths {
		normRegistry := normalizeRegistry(registry)
		if normRegistry == domain {
			creds := imagescan.RegistryCredentials{
				Authority: normRegistry,
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
			return creds, true
		}
	}
	return imagescan.RegistryCredentials{}, false
}
