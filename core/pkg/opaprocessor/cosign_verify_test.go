package opaprocessor

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	cbundle "github.com/sigstore/cosign/v3/pkg/cosign/bundle"
	"github.com/sigstore/cosign/v3/pkg/oci"
	"github.com/sigstore/cosign/v3/pkg/oci/mutate"
	ociremote "github.com/sigstore/cosign/v3/pkg/oci/remote"
	"github.com/sigstore/cosign/v3/pkg/oci/static"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_verify(t *testing.T) {
	type args struct {
		img string
		key string
	}
	tests := []struct {
		name    string
		args    args
		want    bool
		wantErr assert.ErrorAssertionFunc
	}{
		{
			"valid signature",
			args{
				img: "quay.io/kubescape/kubescape:v3.0.3",
				key: "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEbgIMZrMTTlEFDLEeZXz+4R/908BG\nEeO70x6oMN7E4JQgzgbCB5rinqhK5t7dB61saVKQTb4P2NGtjPjXVbSTwQ==\n-----END PUBLIC KEY-----\n",
			},
			true,
			assert.NoError,
		},
		{
			"wrong signature",
			args{
				img: "quay.io/kubescape/kubescape:v2.9.2",
				key: "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEbgIMZrMTTlEFDLEeZXz+4R/908BG\nEeO70x6oMN7E4JQgzgbCB5rinqhK5t7dB61saVKQTb4P2NGtjPjXVbSTwQ==\n-----END PUBLIC KEY-----\n",
			},
			false,
			assert.Error,
		},
		{
			"no matching signature",
			args{
				img: "quay.io/kubescape/kubescape:v2.0.171",
				key: "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEbgIMZrMTTlEFDLEeZXz+4R/908BG\nEeO70x6oMN7E4JQgzgbCB5rinqhK5t7dB61saVKQTb4P2NGtjPjXVbSTwQ==\n-----END PUBLIC KEY-----\n",
			},
			false,
			assert.Error,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := verify(context.Background(), tt.args.img, tt.args.key)
			if !tt.wantErr(t, err, fmt.Sprintf("verify(%v, %v)", tt.args.img, tt.args.key)) {
				return
			}
			assert.Equalf(t, tt.want, got, "verify(%v, %v)", tt.args.img, tt.args.key)
		})
	}
}

func TestVerify_CancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := verify(
		ctx,
		"quay.io/kubescape/kubescape:v3.0.3",
		"-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEbgIMZrMTTlEFDLEeZXz+4R/908BG\nEeO70x6oMN7E4JQgzgbCB5rinqhK5t7dB61saVKQTb4P2NGtjPjXVbSTwQ==\n-----END PUBLIC KEY-----\n",
	)

	require.Error(t, err)
	require.ErrorIs(t, err, context.Canceled)
}

func TestVerify_DeadlineExceeded(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()

	time.Sleep(time.Millisecond)

	_, err := verify(
		ctx,
		"quay.io/kubescape/kubescape:v3.0.3",
		"-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEbgIMZrMTTlEFDLEeZXz+4R/908BG\nEeO70x6oMN7E4JQgzgbCB5rinqhK5t7dB61saVKQTb4P2NGtjPjXVbSTwQ==\n-----END PUBLIC KEY-----\n",
	)

	require.Error(t, err)
	require.ErrorIs(t, err, context.DeadlineExceeded)
}

// TestVerify_RejectsSignatureForAnotherImage checks that verify accepts a
// signature only for the image digest named in its signed payload, as
// `cosign verify` does by default.
//
// Everything runs locally: an in-memory registry holds the images, and the
// Rekor bundle is signed by a throwaway log key trusted through
// SIGSTORE_REKOR_PUBLIC_KEY, so no network or TUF root is needed.
func TestVerify_RejectsSignatureForAnotherImage(t *testing.T) {
	signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	logKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	rekorPub := filepath.Join(t.TempDir(), "rekor.pub")
	require.NoError(t, os.WriteFile(rekorPub, publicKeyPEM(t, &logKey.PublicKey), 0o600))
	t.Setenv("SIGSTORE_REKOR_PUBLIC_KEY", rekorPub)

	server := httptest.NewServer(registry.New(registry.Logger(log.New(io.Discard, "", 0))))
	t.Cleanup(server.Close)
	host := strings.TrimPrefix(server.URL, "http://")

	signed := pushRandomImage(t, host+"/test/signed")
	other := pushRandomImage(t, host+"/test/other")

	sig := signImageDigest(t, signer, logKey, signed)
	attachSignature(t, signed, sig)
	attachSignature(t, other, sig)

	key := string(publicKeyPEM(t, &signer.PublicKey))

	// The signature is valid for the image it names; without this the
	// rejection below could come from a broken setup rather than the claim.
	ok, err := verify(context.Background(), signed.String(), key)
	require.NoError(t, err)
	assert.True(t, ok)

	ok, err = verify(context.Background(), other.String(), key)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid or missing digest in claim")
	assert.False(t, ok)
}

func publicKeyPEM(t *testing.T, pub *ecdsa.PublicKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

func pushRandomImage(t *testing.T, repo string) name.Digest {
	t.Helper()
	img, err := random.Image(256, 1)
	require.NoError(t, err)
	tag, err := name.NewTag(repo + ":latest")
	require.NoError(t, err)
	require.NoError(t, remote.Write(tag, img))
	h, err := img.Digest()
	require.NoError(t, err)
	return tag.Context().Digest(h.String())
}

// signImageDigest signs a cosign simple-signing payload naming img, and wraps
// it in a Rekor bundle signed by logKey, as `cosign sign` would upload it.
func signImageDigest(t *testing.T, signer, logKey *ecdsa.PrivateKey, img name.Digest) oci.Signature {
	t.Helper()

	payload := []byte(fmt.Sprintf(
		`{"critical":{"identity":{"docker-reference":%q},"image":{"docker-manifest-digest":%q},"type":"cosign container image signature"},"optional":null}`,
		img.Context().String(), img.DigestStr()))
	payloadHash := sha256.Sum256(payload)
	rawSig, err := ecdsa.SignASN1(rand.Reader, signer, payloadHash[:])
	require.NoError(t, err)
	b64Sig := base64.StdEncoding.EncodeToString(rawSig)

	entry, err := json.Marshal(map[string]any{
		"apiVersion": "0.0.1",
		"kind":       "hashedrekord",
		"spec": map[string]any{
			"data": map[string]any{"hash": map[string]any{
				"algorithm": "sha256",
				"value":     hex.EncodeToString(payloadHash[:]),
			}},
			"signature": map[string]any{
				"content":   b64Sig,
				"publicKey": map[string]any{"content": base64.StdEncoding.EncodeToString(publicKeyPEM(t, &signer.PublicKey))},
			},
		},
	})
	require.NoError(t, err)

	logKeyDER, err := x509.MarshalPKIXPublicKey(&logKey.PublicKey)
	require.NoError(t, err)
	logID := sha256.Sum256(logKeyDER)

	rekorPayload := cbundle.RekorPayload{
		Body:           base64.StdEncoding.EncodeToString(entry),
		IntegratedTime: time.Now().Unix(),
		LogIndex:       1,
		LogID:          hex.EncodeToString(logID[:]),
	}
	contents, err := json.Marshal(rekorPayload)
	require.NoError(t, err)
	canonical, err := jsoncanonicalizer.Transform(contents)
	require.NoError(t, err)
	setHash := sha256.Sum256(canonical)
	set, err := ecdsa.SignASN1(rand.Reader, logKey, setHash[:])
	require.NoError(t, err)

	sig, err := static.NewSignature(payload, b64Sig, static.WithBundle(&cbundle.RekorBundle{
		SignedEntryTimestamp: set,
		Payload:              rekorPayload,
	}))
	require.NoError(t, err)
	return sig
}

// attachSignature stores sig on img's signature tag.
func attachSignature(t *testing.T, img name.Digest, sig oci.Signature) {
	t.Helper()
	se, err := ociremote.SignedEntity(img)
	require.NoError(t, err)
	se, err = mutate.AttachSignatureToEntity(se, sig)
	require.NoError(t, err)
	require.NoError(t, ociremote.WriteSignatures(img.Context(), se))
}
