package imagescan

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGitlabFailedReloginInvalidatesSession(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/graphql" {
			auth := r.Header.Get("Authorization")
			switch auth {
			case "Bearer goodtoken":
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"data":{"currentUser":{"username":"testuser"}}}`))
			case "Bearer badtoken":
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte("unauthorized"))
			case "Bearer nulluser":
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"data":{"currentUser":null}}`))
			case "Bearer emptyusername":
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"data":{"currentUser":{"username":""}}}`))
			case "Bearer grapherror":
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"errors":[{"message":"Forbidden"}]}`))
			case "Bearer badjson":
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{not-json}`))
			default:
				w.WriteHeader(http.StatusForbidden)
			}
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	tests := []struct {
		name        string
		registry    string
		credentials RegistryCredentials
	}{
		{
			name:        "empty_token",
			registry:    server.URL,
			credentials: RegistryCredentials{Token: ""},
		},
		{
			name:        "unauthorized",
			registry:    server.URL,
			credentials: RegistryCredentials{Token: "badtoken"},
		},
		{
			name:        "null_user",
			registry:    server.URL,
			credentials: RegistryCredentials{Token: "nulluser"},
		},
		{
			name:        "empty_username",
			registry:    server.URL,
			credentials: RegistryCredentials{Token: "emptyusername"},
		},
		{
			name:        "graphql_error",
			registry:    server.URL,
			credentials: RegistryCredentials{Token: "grapherror"},
		},
		{
			name:        "bad_json",
			registry:    server.URL,
			credentials: RegistryCredentials{Token: "badjson"},
		},
		{
			name:        "network_failure",
			registry:    "http://127.0.0.1:1",
			credentials: RegistryCredentials{Token: "goodtoken"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			adaptor := NewGitlabAdaptor()

			// Initial login succeeds
			require.NoError(t, adaptor.Login(ctx, server.URL, RegistryCredentials{Token: "goodtoken"}))
			require.NotNil(t, adaptor.client)

			// Failed re-login must clear session state
			err := adaptor.Login(ctx, tt.registry, tt.credentials)
			require.Error(t, err)
			require.Nil(t, adaptor.client)

			images := []ContainerImageIdentifier{{Registry: "registry.gitlab.com", Repository: "team/app", Hash: "sha256:abc"}}

			statuses, err := adaptor.GetImagesScanStatus(ctx, images)
			require.ErrorContains(t, err, "gitlab client not initialized")
			require.Nil(t, statuses)

			reports, err := adaptor.GetImagesVulnerabilities(ctx, images)
			require.ErrorContains(t, err, "gitlab client not initialized")
			require.Nil(t, reports)

			infos, err := adaptor.GetImagesInformation(ctx, images)
			require.ErrorContains(t, err, "gitlab client not initialized")
			require.Nil(t, infos)

			// Subsequent valid login restores normal operation
			require.NoError(t, adaptor.Login(ctx, server.URL, RegistryCredentials{Token: "goodtoken"}))
			require.NotNil(t, adaptor.client)
		})
	}
}

func TestGitlabFirstLoginFailureLeavesNoSession(t *testing.T) {
	ctx := context.Background()
	adaptor := NewGitlabAdaptor()

	err := adaptor.Login(ctx, "http://127.0.0.1:1", RegistryCredentials{Token: "goodtoken"})
	require.Error(t, err)
	require.Nil(t, adaptor.client)

	images := []ContainerImageIdentifier{{Registry: "registry.gitlab.com", Repository: "team/app", Hash: "sha256:abc"}}
	statuses, err := adaptor.GetImagesScanStatus(ctx, images)
	require.ErrorContains(t, err, "gitlab client not initialized")
	require.Nil(t, statuses)
}

func TestGitlabDestroyInvalidatesSession(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/graphql" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"data":{"currentUser":{"username":"testuser"}}}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	ctx := context.Background()
	adaptor := NewGitlabAdaptor()

	require.NoError(t, adaptor.Login(ctx, server.URL, RegistryCredentials{Token: "goodtoken"}))
	require.NotNil(t, adaptor.client)

	require.NoError(t, adaptor.Destroy())
	require.Nil(t, adaptor.client)

	images := []ContainerImageIdentifier{{Registry: "registry.gitlab.com", Repository: "team/app", Hash: "sha256:abc"}}
	statuses, err := adaptor.GetImagesScanStatus(ctx, images)
	require.ErrorContains(t, err, "gitlab client not initialized")
	require.Nil(t, statuses)
}

func TestGitlabConcurrentScanAndSessionInvalidation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/graphql" {
			auth := r.Header.Get("Authorization")
			if auth == "Bearer goodtoken" {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"data":{"currentUser":{"username":"testuser"},"project":{"fullPath":"team/app","vulnerabilities":{"nodes":[{"title":"CVE-2024-0001","severity":"HIGH","description":"test","location":{"image":"registry.gitlab.com/team/app:latest"}}]}}}}`))
				return
			}
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte("unauthorized"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	ctx := context.Background()
	adaptor := NewGitlabAdaptor()
	require.NoError(t, adaptor.Login(ctx, server.URL, RegistryCredentials{Token: "goodtoken"}))

	var wg sync.WaitGroup
	images := []ContainerImageIdentifier{{Registry: "registry.gitlab.com", Repository: "team/app", Tag: "latest"}}

	// Launch concurrent readers performing scans and information fetches
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				_, _ = adaptor.GetImagesScanStatus(ctx, images)
				_, _ = adaptor.GetImagesVulnerabilities(ctx, images)
				_, _ = adaptor.GetImagesInformation(ctx, images)
			}
		}()
	}

	// Concurrently attempt re-logins and destroys
	wg.Add(1)
	go func() {
		defer wg.Done()
		for j := 0; j < 20; j++ {
			_ = adaptor.Login(ctx, server.URL, RegistryCredentials{Token: "badtoken"})
			_ = adaptor.Destroy()
			_ = adaptor.Login(ctx, server.URL, RegistryCredentials{Token: "goodtoken"})
		}
	}()

	wg.Wait()
}

func TestGitlabInflightInvalidation(t *testing.T) {
	for _, op := range []string{"status", "vulnerabilities"} {
		for _, invalidator := range []string{"destroy", "login_empty"} {
			t.Run(op+"_"+invalidator, func(t *testing.T) {
				pauseCh := make(chan struct{})
				resumeCh := make(chan struct{})
				var once sync.Once

				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == "/api/graphql" {
						auth := r.Header.Get("Authorization")
						if auth == "Bearer goodtoken" {
							w.WriteHeader(http.StatusOK)
							body := make([]byte, 2048)
							n, _ := r.Body.Read(body)
							reqStr := string(body[:n])
							if strings.Contains(reqStr, "ResolveRegistryProject") {
								once.Do(func() {
									close(pauseCh)
									<-resumeCh
								})
								_, _ = w.Write([]byte(`{"data":{"project":{"fullPath":"team/app"}}}`))
								return
							}
							if strings.Contains(reqStr, "currentUser") {
								_, _ = w.Write([]byte(`{"data":{"currentUser":{"username":"testuser"}}}`))
								return
							}
							_, _ = w.Write([]byte(`{"data":{"project":{"vulnerabilities":{"pageInfo":{"hasNextPage":false},"nodes":[{"title":"CVE-2024-0001","severity":"HIGH","description":"test","location":{"image":"registry.gitlab.com/team/app:latest"}}]}}}}`))
							return
						}
						w.WriteHeader(http.StatusUnauthorized)
						_, _ = w.Write([]byte("unauthorized"))
						return
					}
					w.WriteHeader(http.StatusNotFound)
				}))
				defer server.Close()

				ctx := context.Background()
				adaptor := NewGitlabAdaptor()
				require.NoError(t, adaptor.Login(ctx, server.URL, RegistryCredentials{Token: "goodtoken"}))

				images := []ContainerImageIdentifier{{Registry: "registry.gitlab.com", Repository: "team/app", Tag: "latest"}}

				doneCh := make(chan error, 1)
				go func() {
					defer func() {
						if r := recover(); r != nil {
							doneCh <- fmt.Errorf("panic: %v", r)
						}
					}()
					if op == "status" {
						statuses, err := adaptor.GetImagesScanStatus(ctx, images)
						if err == nil && len(statuses) > 0 {
							doneCh <- nil
						} else {
							doneCh <- err
						}
					} else {
						reports, err := adaptor.GetImagesVulnerabilities(ctx, images)
						if err == nil && len(reports) > 0 {
							doneCh <- nil
						} else {
							doneCh <- err
						}
					}
				}()

				// Wait until the lookup has started and paused
				<-pauseCh

				// Invalidate the session in flight
				if invalidator == "destroy" {
					require.NoError(t, adaptor.Destroy())
				} else {
					require.Error(t, adaptor.Login(ctx, server.URL, RegistryCredentials{Token: ""}))
				}

				// Resume the lookup
				close(resumeCh)

				// Verify the scan finishes without panicking
				err := <-doneCh
				require.NoError(t, err)
			})
		}
	}
}
