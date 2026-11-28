package imagescan

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// registryAPIHTTPClient limits credential-bearing API redirects to the
// original origin. TLS alone is not sufficient: Go forwards Authorization
// to another port on the same hostname and to subdomains.
func registryAPIHTTPClient(base *http.Client) *http.Client {
	var client http.Client
	if base != nil {
		client = *base
	}
	callerPolicy := client.CheckRedirect
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		// Snapshot credential-bearing origins before the caller can mutate
		// either the destination request or the redirect history.
		var origins []url.URL
		for _, previous := range via {
			if previous.Header.Get("Authorization") != "" || previous.URL.User != nil {
				origins = append(origins, *previous.URL)
			}
		}
		validate := func() error {
			if req.URL == nil {
				return errors.New("refusing registry redirect: destination URL is missing")
			}
			for _, origin := range origins {
				if !sameRegistryAPIOrigin(&origin, req.URL) {
					return fmt.Errorf("refusing registry redirect: credentials cannot leave origin %s for %s", origin.Host, req.URL.Host)
				}
			}
			return nil
		}
		if err := validate(); err != nil {
			return err
		}
		if callerPolicy != nil {
			if err := callerPolicy(req, via); err != nil {
				return err
			}
			return validate()
		}
		if len(via) >= 10 {
			return errors.New("stopped after 10 redirects")
		}
		return nil
	}
	return &client
}

func sameRegistryAPIOrigin(a, b *url.URL) bool {
	port := func(u *url.URL) string {
		if u.Port() != "" {
			return u.Port()
		}
		if strings.EqualFold(u.Scheme, "https") {
			return "443"
		}
		return "80"
	}
	return strings.EqualFold(a.Scheme, b.Scheme) &&
		strings.EqualFold(a.Hostname(), b.Hostname()) && port(a) == port(b)
}

// parseRegistryHostAndScheme normalizes a registry host or URL into its transport
// scheme ("https" by default, or "http") and trimmed host.
func parseRegistryHostAndScheme(registry string) (string, string, error) {
	trimmed := strings.TrimSpace(registry)
	if trimmed == "" {
		return "", "", errors.New("registry host cannot be empty")
	}
	lower := strings.ToLower(trimmed)
	scheme := "https"
	host := trimmed
	if strings.HasPrefix(lower, "http://") {
		scheme = "http"
		host = trimmed[len("http://"):]
	} else if strings.HasPrefix(lower, "https://") {
		host = trimmed[len("https://"):]
	}
	host = strings.TrimRight(host, "/")
	if host == "" {
		return "", "", errors.New("registry host cannot be empty")
	}
	return scheme, host, nil
}

// validateRegistryLoginSecurity enforces credentials.Authority binding and refuses
// transmitting credentials over plain HTTP unless explicitly opted in.
func validateRegistryLoginSecurity(scheme, host string, credentials RegistryCredentials, allowInsecureHTTP bool, optInOption string) error {
	if trimmedAuth := strings.TrimSpace(credentials.Authority); trimmedAuth != "" {
		_, authHost, err := parseRegistryHostAndScheme(trimmedAuth)
		if err != nil || !strings.EqualFold(authHost, host) {
			return fmt.Errorf("credentials authority %q does not match registry host %q", credentials.Authority, host)
		}
	}
	if strings.EqualFold(scheme, "http") && credentials.hasAuthenticator() && !allowInsecureHTTP {
		return fmt.Errorf("refusing to send credentials over plain http to %s; use https or enable %s", host, optInOption)
	}
	return nil
}
