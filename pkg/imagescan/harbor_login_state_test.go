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

func TestHarborFailedReloginInvalidatesSession(t *testing.T) {
	goodServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v2.0/systeminfo" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"with_chartmuseum": true}`))
			return
		}
		if strings.Contains(r.URL.Path, "/artifacts/") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{
				"scan_overview": {
					"application/vnd.security.vulnerability.report; version=1.1": {
						"scan_status": "Success",
						"end_time": "2024-01-01T10:00:00Z"
					}
				}
			}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer goodServer.Close()

	badServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v2.0/systeminfo" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer badServer.Close()

	serverErrorServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v2.0/systeminfo" {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer serverErrorServer.Close()

	tests := []struct {
		name        string
		registry    string
		credentials RegistryCredentials
	}{
		{
			name:        "unauthorized",
			registry:    badServer.URL,
			credentials: RegistryCredentials{Username: "bad", Password: "bad"},
		},
		{
			name:        "server_error",
			registry:    serverErrorServer.URL,
			credentials: RegistryCredentials{},
		},
		{
			name:        "network_failure",
			registry:    "http://127.0.0.1:1",
			credentials: RegistryCredentials{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			adaptor := NewHarborAdaptor()

			// Initial login succeeds
			require.NoError(t, adaptor.Login(ctx, goodServer.URL, RegistryCredentials{Username: "user", Password: "pwd"}))
			require.NotNil(t, adaptor.client)
			require.Equal(t, goodServer.URL, adaptor.host)

			// Failed re-login must clear session state and host
			err := adaptor.Login(ctx, tt.registry, tt.credentials)
			require.Error(t, err)
			require.Nil(t, adaptor.client)
			require.Empty(t, adaptor.host)

			images := []ContainerImageIdentifier{{Registry: goodServer.URL, Repository: "project/app", Hash: "sha256:abc"}}

			statuses, err := adaptor.GetImagesScanStatus(ctx, images)
			require.ErrorContains(t, err, "harbor client not initialized")
			require.Nil(t, statuses)

			reports, err := adaptor.GetImagesVulnerabilities(ctx, images)
			require.ErrorContains(t, err, "harbor client not initialized")
			require.Nil(t, reports)

			infos, err := adaptor.GetImagesInformation(ctx, images)
			require.ErrorContains(t, err, "harbor client not initialized")
			require.Nil(t, infos)

			// Subsequent valid login restores normal operation
			require.NoError(t, adaptor.Login(ctx, goodServer.URL, RegistryCredentials{Username: "user", Password: "pwd"}))
			require.NotNil(t, adaptor.client)
			require.Equal(t, goodServer.URL, adaptor.host)
		})
	}
}

func TestHarborFirstLoginFailureLeavesNoSession(t *testing.T) {
	ctx := context.Background()
	adaptor := NewHarborAdaptor()

	err := adaptor.Login(ctx, "http://127.0.0.1:1", RegistryCredentials{})
	require.Error(t, err)
	require.Nil(t, adaptor.client)
	require.Empty(t, adaptor.host)

	images := []ContainerImageIdentifier{{Registry: "harbor.example", Repository: "project/app", Hash: "sha256:abc"}}
	statuses, err := adaptor.GetImagesScanStatus(ctx, images)
	require.ErrorContains(t, err, "harbor client not initialized")
	require.Nil(t, statuses)
}

func TestHarborDestroyInvalidatesSession(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v2.0/systeminfo" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"with_chartmuseum": true}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	ctx := context.Background()
	adaptor := NewHarborAdaptor()

	require.NoError(t, adaptor.Login(ctx, server.URL, RegistryCredentials{}))
	require.NotNil(t, adaptor.client)
	require.Equal(t, server.URL, adaptor.host)

	require.NoError(t, adaptor.Destroy())
	require.Nil(t, adaptor.client)
	require.Empty(t, adaptor.host)

	// Destroy is idempotent
	require.NoError(t, adaptor.Destroy())

	images := []ContainerImageIdentifier{{Registry: server.URL, Repository: "project/app", Hash: "sha256:abc"}}
	statuses, err := adaptor.GetImagesScanStatus(ctx, images)
	require.ErrorContains(t, err, "harbor client not initialized")
	require.Nil(t, statuses)
}

func TestHarborConcurrentScanAndSessionInvalidation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v2.0/systeminfo" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"with_chartmuseum": true}`))
			return
		}
		if strings.Contains(r.URL.Path, "/artifacts/") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{
				"scan_overview": {
					"application/vnd.security.vulnerability.report; version=1.1": {
						"scan_status": "Success",
						"end_time": "2024-01-01T10:00:00Z"
					}
				}
			}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	ctx := context.Background()
	adaptor := NewHarborAdaptor()
	require.NoError(t, adaptor.Login(ctx, server.URL, RegistryCredentials{}))

	var wg sync.WaitGroup
	images := []ContainerImageIdentifier{{Registry: server.URL, Repository: "project/app", Tag: "latest"}}

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
			_ = adaptor.Login(ctx, "http://127.0.0.1:1", RegistryCredentials{})
			_ = adaptor.Destroy()
			_ = adaptor.Login(ctx, server.URL, RegistryCredentials{})
		}
	}()

	wg.Wait()
}

func TestHarborInflightInvalidation(t *testing.T) {
	for _, op := range []string{"status", "vulnerabilities"} {
		for _, invalidator := range []string{"destroy", "login_failure"} {
			t.Run(op+"_"+invalidator, func(t *testing.T) {
				pauseCh := make(chan struct{})
				resumeCh := make(chan struct{})
				var once sync.Once

				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == "/api/v2.0/systeminfo" {
						w.WriteHeader(http.StatusOK)
						_, _ = w.Write([]byte(`{"with_chartmuseum": true}`))
						return
					}
					if strings.Contains(r.URL.Path, "/artifacts/") {
						once.Do(func() {
							close(pauseCh)
							<-resumeCh
						})
						w.WriteHeader(http.StatusOK)
						if strings.Contains(r.URL.Path, "additions/vulnerabilities") {
							_, _ = w.Write([]byte(`{
								"application/vnd.security.vulnerability.report; version=1.1": {
									"vulnerabilities": [
										{"id": "CVE-2024-0001", "severity": "High", "description": "test", "links": []}
									]
								}
							}`))
						} else {
							_, _ = w.Write([]byte(`{
								"scan_overview": {
									"application/vnd.security.vulnerability.report; version=1.1": {
										"scan_status": "Success",
										"end_time": "2024-01-01T10:00:00Z"
									}
								}
							}`))
						}
						return
					}
					w.WriteHeader(http.StatusNotFound)
				}))
				defer server.Close()

				ctx := context.Background()
				adaptor := NewHarborAdaptor()
				require.NoError(t, adaptor.Login(ctx, server.URL, RegistryCredentials{}))

				images := []ContainerImageIdentifier{{Registry: server.URL, Repository: "project/app", Hash: "sha256:abc"}}

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
					require.Error(t, adaptor.Login(ctx, "http://127.0.0.1:1", RegistryCredentials{}))
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
