package opaprocessor

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/sigstore/cosign/v3/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_has_signature(t *testing.T) {

	tests := []struct {
		name string
		img  string
		want bool
	}{
		{
			name: "valid signature",
			img:  "quay.io/kubescape/gateway",
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, has_signature(context.Background(), tt.img), tt.name)
		})
	}
}

func Test_has_signature_SigstoreBundle(t *testing.T) {
	server := httptest.NewServer(registry.New(registry.Logger(log.New(io.Discard, "", 0))))
	t.Cleanup(server.Close)
	repo := strings.TrimPrefix(server.URL, "http://") + "/test/signed"
	signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	unsigned := pushRandomImage(t, repo)

	legacy := pushRandomImage(t, repo)
	attachSignature(t, legacy, signImageDigestWithoutBundle(t, signer, legacy))

	bundled := pushRandomImage(t, repo)
	attachBundle(t, bundled, bundled, signer, nil, types.CosignSignPredicateType)

	provenanceOnly := pushRandomImage(t, repo)
	attachBundle(t, provenanceOnly, provenanceOnly, signer, nil, "https://slsa.dev/provenance/v1")

	otherSubject := pushRandomImage(t, repo)
	attachBundle(t, otherSubject, pushRandomImage(t, repo), signer, nil, types.CosignSignPredicateType)

	taggedRepo := strings.TrimPrefix(server.URL, "http://") + "/test/tagged"
	tagged := pushRandomImage(t, taggedRepo)
	attachBundle(t, tagged, tagged, signer, nil, types.CosignSignPredicateType)

	tests := []struct {
		name string
		img  string
		want bool
	}{
		{name: "unsigned image", img: unsigned.String(), want: false},
		{name: "legacy signature", img: legacy.String(), want: true},
		{name: "sigstore bundle signature", img: bundled.String(), want: true},
		{name: "sigstore bundle signature by tag", img: taggedRepo + ":latest", want: true},
		{name: "attestation bundle is not a signature", img: provenanceOnly.String(), want: false},
		{name: "bundle signs another image", img: otherSubject.String(), want: false},
		{name: "missing image", img: repo + ":missing", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, has_signature(context.Background(), tt.img))
		})
	}
}

func Test_has_signature_MissingImageFetchesManifestOnce(t *testing.T) {
	var manifestRequests atomic.Int32
	handler := registry.New(registry.Logger(log.New(io.Discard, "", 0)))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/manifests/") {
			manifestRequests.Add(1)
		}
		handler.ServeHTTP(w, r)
	}))
	t.Cleanup(server.Close)

	assert.False(t, has_signature(context.Background(), strings.TrimPrefix(server.URL, "http://")+"/test/absent:1.0"))
	assert.Equal(t, int32(1), manifestRequests.Load())
}

func Test_has_signature_CancelledContext(t *testing.T) {
	server := httptest.NewServer(registry.New(registry.Logger(log.New(io.Discard, "", 0))))
	t.Cleanup(server.Close)
	signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	img := pushRandomImage(t, strings.TrimPrefix(server.URL, "http://")+"/test/signed")
	attachBundle(t, img, img, signer, nil, types.CosignSignPredicateType)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	assert.False(t, has_signature(ctx, img.String()))
}

func Test_has_signature_CancelledDuringBundleLookup(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	handler := registry.New(registry.Logger(log.New(io.Discard, "", 0)))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/referrers/") {
			cancel()
			select {
			case <-r.Context().Done():
			case <-time.After(10 * time.Second):
			}
			return
		}
		handler.ServeHTTP(w, r)
	}))
	t.Cleanup(server.Close)
	img := pushRandomImage(t, strings.TrimPrefix(server.URL, "http://")+"/test/stalled")

	start := time.Now()
	assert.False(t, has_signature(ctx, img.String()))
	assert.Less(t, time.Since(start), 5*time.Second)
}
