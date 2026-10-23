package imagescan

import (
	"fmt"
	"net/url"
	"strings"
)

// validateImageRegistry prevents a repository/tag collision at another
// registry from being reported as findings belonging to the requested image.
// Empty registry fields retain the legacy single-registry calling convention.
func (a *HarborAdaptor) validateImageRegistry(image ContainerImageIdentifier, host string) error {
	if image.Registry == "" || host == "" {
		return nil
	}
	actual, err := harborRegistryAuthority(image.Registry)
	if err != nil {
		return err
	}
	expected, err := harborRegistryAuthority(host)
	if err != nil {
		return err
	}
	if actual != expected {
		return fmt.Errorf("image registry %q does not match logged-in Harbor registry %q", image.Registry, host)
	}
	return nil
}

func harborRegistryAuthority(registry string) (string, error) {
	value := registry
	if !strings.Contains(value, "://") {
		value = "https://" + value
	}
	u, err := url.Parse(value)
	if err != nil || u.Hostname() == "" || u.User != nil ||
		(u.Scheme != "http" && u.Scheme != "https") ||
		(u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("invalid Harbor registry authority")
	}
	return strings.ToLower(u.Host), nil
}
