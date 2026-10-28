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
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/resources"
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
	unbundled := signImageDigestWithoutBundle(t, signer, img)
	rekorPayload, set := rekorEntry(t, signer, logKey, unbundled)
	payload, err := unbundled.Payload()
	require.NoError(t, err)
	b64Sig, err := unbundled.Base64Signature()
	require.NoError(t, err)
	sig, err := static.NewSignature(payload, b64Sig, static.WithBundle(&cbundle.RekorBundle{
		SignedEntryTimestamp: set,
		Payload:              rekorPayload,
	}))
	require.NoError(t, err)
	return sig
}

// rekorEntry builds the hashedrekord log entry Rekor would record for sig, and
// its signed entry timestamp signed by logKey.
func rekorEntry(t *testing.T, signer, logKey *ecdsa.PrivateKey, sig oci.Signature) (cbundle.RekorPayload, []byte) {
	t.Helper()
	payload, err := sig.Payload()
	require.NoError(t, err)
	b64Sig, err := sig.Base64Signature()
	require.NoError(t, err)
	payloadHash := sha256.Sum256(payload)

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
		LogIndex:       0,
		LogID:          hex.EncodeToString(logID[:]),
	}
	contents, err := json.Marshal(rekorPayload)
	require.NoError(t, err)
	canonical, err := jsoncanonicalizer.Transform(contents)
	require.NoError(t, err)
	setHash := sha256.Sum256(canonical)
	set, err := ecdsa.SignASN1(rand.Reader, logKey, setHash[:])
	require.NoError(t, err)
	return rekorPayload, set
}

// rekorSearchResponse is the body Rekor answers POST
// /api/v1/log/entries/retrieve with when it holds sig: the entry keyed by its
// UUID, with its signed entry timestamp and an inclusion proof in a log of one
// entry, whose root hash is the entry's own RFC 6962 leaf hash.
func rekorSearchResponse(t *testing.T, signer, logKey *ecdsa.PrivateKey, sig oci.Signature) []byte {
	t.Helper()
	rekorPayload, set := rekorEntry(t, signer, logKey, sig)
	body, err := base64.StdEncoding.DecodeString(rekorPayload.Body.(string))
	require.NoError(t, err)
	leaf := sha256.Sum256(append([]byte{0}, body...))
	leafHash := hex.EncodeToString(leaf[:])

	resp, err := json.Marshal([]map[string]any{{
		leafHash: map[string]any{
			"body":           rekorPayload.Body,
			"integratedTime": rekorPayload.IntegratedTime,
			"logIndex":       rekorPayload.LogIndex,
			"logID":          rekorPayload.LogID,
			"verification": map[string]any{
				"signedEntryTimestamp": set,
				"inclusionProof": map[string]any{
					"logIndex": 0,
					"treeSize": 1,
					"rootHash": leafHash,
					"hashes":   []string{},
				},
			},
		},
	}})
	require.NoError(t, err)
	return resp
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

// TestVerify_TransparencyLogPolicy covers the cosignRequireTransparencyLog
// control input. An image signed with `cosign sign --tlog-upload=false` has no
// Rekor bundle; by default it must still be rejected, as `cosign verify --key`
// does, and setting the input to "false" must accept it without loosening the
// key or claim checks.
func TestVerify_TransparencyLogPolicy(t *testing.T) {
	signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	otherSigner, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	logKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Trust a throwaway log key so the default path stays offline.
	rekorPub := filepath.Join(t.TempDir(), "rekor.pub")
	require.NoError(t, os.WriteFile(rekorPub, publicKeyPEM(t, &logKey.PublicKey), 0o600))
	t.Setenv("SIGSTORE_REKOR_PUBLIC_KEY", rekorPub)

	server := httptest.NewServer(registry.New(registry.Logger(log.New(io.Discard, "", 0))))
	t.Cleanup(server.Close)
	host := strings.TrimPrefix(server.URL, "http://")

	signed := pushRandomImage(t, host+"/test/signed")
	attachSignature(t, signed, signImageDigestWithoutBundle(t, signer, signed))

	byOtherKey := pushRandomImage(t, host+"/test/other-key")
	attachSignature(t, byOtherKey, signImageDigestWithoutBundle(t, otherSigner, byOtherKey))

	otherImage := pushRandomImage(t, host+"/test/other-image")
	attachSignature(t, otherImage, signImageDigestWithoutBundle(t, signer, signed))

	key := string(publicKeyPEM(t, &signer.PublicKey))
	withInput := func(v string) context.Context {
		return withCosignPolicy(context.Background(), map[string][]string{cosignRequireTransparencyLogInput: {v}})
	}

	tests := []struct {
		name    string
		ctx     context.Context
		img     name.Digest
		want    bool
		wantErr string
	}{
		{name: "no input requires a tlog entry", ctx: context.Background(), img: signed, wantErr: "rekor client not provided"},
		{name: "true requires a tlog entry", ctx: withInput("true"), img: signed, wantErr: "rekor client not provided"},
		{name: "false accepts a key-signed image without a tlog entry", ctx: withInput("false"), img: signed, want: true},
		{name: "false still rejects a signature by another key", ctx: withInput("false"), img: byOtherKey, wantErr: "no matching signatures"},
		{name: "false still checks the signed digest", ctx: withInput("false"), img: otherImage, wantErr: "invalid or missing digest in claim"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ok, err := verify(tt.ctx, tt.img.String(), key)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, tt.want, ok)
		})
	}
}

// TestVerify_IgnoreTlogDoesNotFetchRekorKeys: with the tlog check off,
// verification must not depend on loading Rekor public keys, which is the
// first thing to fail in an air-gapped cluster.
func TestVerify_IgnoreTlogDoesNotFetchRekorKeys(t *testing.T) {
	signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	t.Setenv("SIGSTORE_REKOR_PUBLIC_KEY", filepath.Join(t.TempDir(), "missing.pub"))

	server := httptest.NewServer(registry.New(registry.Logger(log.New(io.Discard, "", 0))))
	t.Cleanup(server.Close)
	img := pushRandomImage(t, strings.TrimPrefix(server.URL, "http://")+"/test/signed")
	attachSignature(t, img, signImageDigestWithoutBundle(t, signer, img))
	key := string(publicKeyPEM(t, &signer.PublicKey))

	_, err = verify(context.Background(), img.String(), key)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "getting Rekor public keys")

	ctx := withCosignPolicy(context.Background(), map[string][]string{cosignRequireTransparencyLogInput: {"false"}})
	ok, err := verify(ctx, img.String(), key)
	require.NoError(t, err)
	assert.True(t, ok)
}

// TestVerify_RekorURL covers the cosignRekorURL control input: when it is set,
// a signature without a Rekor bundle is looked up online in that Rekor, like
// `cosign verify --rekor-url`, and the entry it returns must carry a signed
// entry timestamp from a trusted log key.
func TestVerify_RekorURL(t *testing.T) {
	signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	logKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	untrustedLogKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	rekorPub := filepath.Join(t.TempDir(), "rekor.pub")
	require.NoError(t, os.WriteFile(rekorPub, publicKeyPEM(t, &logKey.PublicKey), 0o600))
	t.Setenv("SIGSTORE_REKOR_PUBLIC_KEY", rekorPub)

	server := httptest.NewServer(registry.New(registry.Logger(log.New(io.Discard, "", 0))))
	t.Cleanup(server.Close)
	img := pushRandomImage(t, strings.TrimPrefix(server.URL, "http://")+"/test/signed")
	sig := signImageDigestWithoutBundle(t, signer, img)
	attachSignature(t, img, sig)
	key := string(publicKeyPEM(t, &signer.PublicKey))

	logged := rekorSearchResponse(t, signer, logKey, sig)
	loggedByUntrustedKey := rekorSearchResponse(t, signer, untrustedLogKey, sig)

	tests := []struct {
		name         string
		inputs       func(rekorURL string) map[string][]string
		response     []byte
		wantErr      string
		wantRequests []string
	}{
		{
			name:    "no input keeps the default",
			inputs:  func(string) map[string][]string { return nil },
			wantErr: "rekor client not provided",
		},
		{
			name:    "empty value keeps the default",
			inputs:  func(string) map[string][]string { return map[string][]string{cosignRekorURLInput: {""}} },
			wantErr: "rekor client not provided",
		},
		{
			name:         "set looks up the signature in that Rekor",
			inputs:       func(u string) map[string][]string { return map[string][]string{cosignRekorURLInput: {u}} },
			response:     []byte("[]"),
			wantErr:      "signature not found in transparency log",
			wantRequests: []string{"POST /api/v1/log/entries/retrieve"},
		},
		{
			name:         "set accepts an entry signed by the trusted log key",
			inputs:       func(u string) map[string][]string { return map[string][]string{cosignRekorURLInput: {u}} },
			response:     logged,
			wantRequests: []string{"POST /api/v1/log/entries/retrieve"},
		},
		{
			name:         "set rejects an entry signed by another log key",
			inputs:       func(u string) map[string][]string { return map[string][]string{cosignRekorURLInput: {u}} },
			response:     loggedByUntrustedKey,
			wantErr:      "rekor log public key not found",
			wantRequests: []string{"POST /api/v1/log/entries/retrieve"},
		},
		{
			name: "ignored when the tlog is not required",
			inputs: func(u string) map[string][]string {
				return map[string][]string{
					cosignRekorURLInput:               {u},
					cosignRequireTransparencyLogInput: {"false"},
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rekor, requests := fakeRekor(t, tt.response)
			ok, err := verify(withCosignPolicy(context.Background(), tt.inputs(rekor.URL)), img.String(), key)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				assert.False(t, ok)
			} else {
				require.NoError(t, err)
				assert.True(t, ok)
			}
			assert.Equal(t, tt.wantRequests, *requests)
		})
	}
}

// fakeRekor serves response to every request, and records the requests.
func fakeRekor(t *testing.T, response []byte) (*httptest.Server, *[]string) {
	t.Helper()
	var requests []string
	rekor := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(response)
	}))
	t.Cleanup(rekor.Close)
	return rekor, &requests
}

func TestWithCosignPolicy(t *testing.T) {
	tests := []struct {
		name   string
		inputs map[string][]string
		want   bool
	}{
		{name: "no inputs", inputs: nil, want: false},
		{name: "input absent", inputs: map[string][]string{"trustedCosignPublicKeys": {"k"}}, want: false},
		{name: "empty value", inputs: map[string][]string{cosignRequireTransparencyLogInput: {}}, want: false},
		{name: "true", inputs: map[string][]string{cosignRequireTransparencyLogInput: {"true"}}, want: false},
		{name: "false", inputs: map[string][]string{cosignRequireTransparencyLogInput: {"false"}}, want: true},
		{name: "false, any case and spacing", inputs: map[string][]string{cosignRequireTransparencyLogInput: {" False "}}, want: true},
		{name: "unrecognised value keeps the check", inputs: map[string][]string{cosignRequireTransparencyLogInput: {"no"}}, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := withCosignPolicy(context.Background(), tt.inputs)
			assert.Equal(t, tt.want, cosignPolicyFrom(ctx).ignoreTlog)
		})
	}
}

func TestWithCosignPolicy_RekorURL(t *testing.T) {
	tests := []struct {
		name   string
		inputs map[string][]string
		want   string
	}{
		{name: "input absent", inputs: map[string][]string{"trustedCosignPublicKeys": {"k"}}, want: ""},
		{name: "empty list", inputs: map[string][]string{cosignRekorURLInput: {}}, want: ""},
		{name: "empty value", inputs: map[string][]string{cosignRekorURLInput: {" "}}, want: ""},
		{name: "set", inputs: map[string][]string{cosignRekorURLInput: {" https://rekor.example.com "}}, want: "https://rekor.example.com"},
		{
			name: "set with the tlog input",
			inputs: map[string][]string{
				cosignRekorURLInput:               {"https://rekor.example.com"},
				cosignRequireTransparencyLogInput: {"true"},
			},
			want: "https://rekor.example.com",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := withCosignPolicy(context.Background(), tt.inputs)
			assert.Equal(t, tt.want, cosignPolicyFrom(ctx).rekorURL)
		})
	}
}

// signImageDigestWithoutBundle signs a cosign simple-signing payload naming
// img, as `cosign sign --key --tlog-upload=false` stores it: no Rekor bundle.
func signImageDigestWithoutBundle(t *testing.T, signer *ecdsa.PrivateKey, img name.Digest) oci.Signature {
	t.Helper()
	payload := []byte(fmt.Sprintf(
		`{"critical":{"identity":{"docker-reference":%q},"image":{"docker-manifest-digest":%q},"type":"cosign container image signature"},"optional":null}`,
		img.Context().String(), img.DigestStr()))
	payloadHash := sha256.Sum256(payload)
	rawSig, err := ecdsa.SignASN1(rand.Reader, signer, payloadHash[:])
	require.NoError(t, err)
	sig, err := static.NewSignature(payload, base64.StdEncoding.EncodeToString(rawSig))
	require.NoError(t, err)
	return sig
}

// verifyImageSignatureRego is regolibrary's verify-image-signature rule, cut
// down to bare Pods.
const verifyImageSignatureRego = `package armo_builtins
import rego.v1

deny contains msga if {
	pod := input[_]
	pod.kind == "Pod"
	container := pod.spec.containers[i]
	verified_keys := [trusted_key | trusted_key = data.postureControlInputs.trustedCosignPublicKeys[_]; cosign.verify(container.image, trusted_key)]
	count(verified_keys) == 0
	msga := {
		"alertMessage": sprintf("signature not verified for image: %v", [container.image]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [],
		"fixPaths": [],
		"alertObject": {"k8sApiObjects": [pod]}
	}
}
`

// TestRunOPAOnSingleRule_CosignTransparencyLogInput evaluates a rule shaped
// like regolibrary's verify-image-signature, to show the control input
// reaches cosign.verify through the rule's posture control inputs.
func TestRunOPAOnSingleRule_CosignTransparencyLogInput(t *testing.T) {
	signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	logKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	rekorPub := filepath.Join(t.TempDir(), "rekor.pub")
	require.NoError(t, os.WriteFile(rekorPub, publicKeyPEM(t, &logKey.PublicKey), 0o600))
	t.Setenv("SIGSTORE_REKOR_PUBLIC_KEY", rekorPub)

	server := httptest.NewServer(registry.New(registry.Logger(log.New(io.Discard, "", 0))))
	t.Cleanup(server.Close)
	img := pushRandomImage(t, strings.TrimPrefix(server.URL, "http://")+"/test/signed")
	attachSignature(t, img, signImageDigestWithoutBundle(t, signer, img))

	rule := &reporthandling.PolicyRule{
		PortalBase:   armotypes.PortalBase{Name: "verify-image-signature"},
		RuleLanguage: reporthandling.RegoLanguage,
		Rule:         verifyImageSignatureRego,
	}
	pod := map[string]any{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata":   map[string]any{"name": "p", "namespace": "default"},
		"spec":       map[string]any{"containers": []any{map[string]any{"name": "c", "image": img.String()}}},
	}
	getRuleData := func(r *reporthandling.PolicyRule) string { return r.Rule }
	key := string(publicKeyPEM(t, &signer.PublicKey))

	run := func(inputs map[string][]string) []reporthandling.RuleResponse {
		opap := &OPAProcessor{compiledModules: make(map[string]compiledRule)}
		responses, _, err := opap.runOPAOnSingleRule(context.Background(), rule, []map[string]any{pod}, getRuleData,
			resources.RegoDependenciesData{PostureControlInputs: inputs}, "C-0236")
		require.NoError(t, err)
		return responses
	}

	assert.Len(t, run(map[string][]string{"trustedCosignPublicKeys": {key}}), 1,
		"without the input a signature with no tlog entry must still fail")
	assert.Empty(t, run(map[string][]string{
		"trustedCosignPublicKeys":         {key},
		cosignRequireTransparencyLogInput: {"false"},
	}), "cosignRequireTransparencyLog=false must let the key-signed image pass")
}

// TestEvaluateRule_CosignTransparencyLogInputNeedsRuleMetadata runs the scan
// path from rule metadata: makeRegoDeps passes a rule only the posture inputs
// its controlConfigInputs declare, so cosignRequireTransparencyLog reaches
// cosign.verify only once regolibrary's verify-image-signature declares it.
func TestEvaluateRule_CosignTransparencyLogInputNeedsRuleMetadata(t *testing.T) {
	signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	logKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	rekorPub := filepath.Join(t.TempDir(), "rekor.pub")
	require.NoError(t, os.WriteFile(rekorPub, publicKeyPEM(t, &logKey.PublicKey), 0o600))
	t.Setenv("SIGSTORE_REKOR_PUBLIC_KEY", rekorPub)

	server := httptest.NewServer(registry.New(registry.Logger(log.New(io.Discard, "", 0))))
	t.Cleanup(server.Close)
	img := pushRandomImage(t, strings.TrimPrefix(server.URL, "http://")+"/test/signed")
	attachSignature(t, img, signImageDigestWithoutBundle(t, signer, img))
	key := string(publicKeyPEM(t, &signer.PublicKey))

	// regolibrary v2.0.37 and earlier declare only the trusted keys.
	releasedRule := verifyImageSignatureRule(t, trustedKeysInput)
	companionRule := verifyImageSignatureRule(t, trustedKeysInput, requireTlogInput)
	pod := podWithImage(img)

	tests := []struct {
		name       string
		rule       *reporthandling.PolicyRule
		tlogInput  []string
		wantInput  bool
		wantFailed bool
	}{
		{name: "released metadata filters out false", rule: releasedRule, tlogInput: []string{"false"}, wantInput: false, wantFailed: true},
		{name: "declared input, unset", rule: companionRule, tlogInput: nil, wantInput: false, wantFailed: true},
		{name: "declared input, default true", rule: companionRule, tlogInput: []string{"true"}, wantInput: true, wantFailed: true},
		{name: "declared input, false", rule: companionRule, tlogInput: []string{"false"}, wantInput: true, wantFailed: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sessionObj := cautils.NewOPASessionObjMock()
			sessionObj.RegoInputData.PostureControlInputs = map[string][]string{"trustedCosignPublicKeys": {key}}
			if tt.tlogInput != nil {
				sessionObj.RegoInputData.PostureControlInputs[cosignRequireTransparencyLogInput] = tt.tlogInput
			}
			proc := NewOPAProcessor(sessionObj, &resources.RegoDependenciesData{}, "", "", "", false, nil)

			_, got := proc.makeRegoDeps(tt.rule.ControlConfigInputs, nil).PostureControlInputs[cosignRequireTransparencyLogInput]
			assert.Equal(t, tt.wantInput, got, "input passed to the rule")

			responses, err := proc.EvaluateRule(context.Background(), tt.rule, []workloadinterface.IMetadata{pod}, "C-0236")
			require.NoError(t, err)
			if tt.wantFailed {
				assert.Len(t, responses, 1, "a signature with no tlog entry must fail")
			} else {
				assert.Empty(t, responses, "the key-signed image must pass")
			}
		})
	}
}

const trustedKeysInput = `{
	"path": "settings.postureControlInputs.trustedCosignPublicKeys",
	"name": "Trusted Cosign public keys",
	"description": "A list of trusted Cosign public keys that are used for validating container image signatures."
}`

const requireTlogInput = `{
	"path": "settings.postureControlInputs.cosignRequireTransparencyLog",
	"name": "Require Cosign transparency log entry",
	"description": "Whether a valid signature must also have a transparency log (Rekor) entry."
}`

const rekorURLInput = `{
	"path": "settings.postureControlInputs.cosignRekorURL",
	"name": "Cosign Rekor URL",
	"description": "The Rekor instance to look up signatures that have no Rekor bundle in."
}`

// verifyImageSignatureRule is regolibrary's verify-image-signature rule, with
// configInputs as the controlConfigInputs its metadata declares.
func verifyImageSignatureRule(t *testing.T, configInputs ...string) *reporthandling.PolicyRule {
	t.Helper()
	var rule reporthandling.PolicyRule
	require.NoError(t, json.Unmarshal([]byte(`{
		"name": "verify-image-signature",
		"ruleLanguage": "Rego",
		"match": [{"apiGroups": [""], "apiVersions": ["v1"], "resources": ["Pod"]}],
		"ruleQuery": "armo_builtins",
		"controlConfigInputs": [`+strings.Join(configInputs, ",")+`]
	}`), &rule))
	rule.Rule = verifyImageSignatureRego
	return &rule
}

func podWithImage(img name.Digest) workloadinterface.IMetadata {
	return workloadinterface.NewWorkloadObj(map[string]any{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata":   map[string]any{"name": "p", "namespace": "default"},
		"spec":       map[string]any{"containers": []any{map[string]any{"name": "c", "image": img.String()}}},
	})
}

// TestEvaluateRule_CosignRekorURLInputNeedsRuleMetadata runs the scan path
// from rule metadata to the Rekor lookup: cosignRekorURL reaches cosign.verify
// only when the rule's controlConfigInputs declare it, and then the image is
// verified against the entry that Rekor returns.
func TestEvaluateRule_CosignRekorURLInputNeedsRuleMetadata(t *testing.T) {
	signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	logKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	rekorPub := filepath.Join(t.TempDir(), "rekor.pub")
	require.NoError(t, os.WriteFile(rekorPub, publicKeyPEM(t, &logKey.PublicKey), 0o600))
	t.Setenv("SIGSTORE_REKOR_PUBLIC_KEY", rekorPub)

	server := httptest.NewServer(registry.New(registry.Logger(log.New(io.Discard, "", 0))))
	t.Cleanup(server.Close)
	img := pushRandomImage(t, strings.TrimPrefix(server.URL, "http://")+"/test/signed")
	sig := signImageDigestWithoutBundle(t, signer, img)
	attachSignature(t, img, sig)
	key := string(publicKeyPEM(t, &signer.PublicKey))
	response := rekorSearchResponse(t, signer, logKey, sig)

	// regolibrary v2.0.38 and earlier do not declare cosignRekorURL.
	releasedRule := verifyImageSignatureRule(t, trustedKeysInput, requireTlogInput)
	companionRule := verifyImageSignatureRule(t, trustedKeysInput, requireTlogInput, rekorURLInput)
	pod := podWithImage(img)

	tests := []struct {
		name         string
		rule         *reporthandling.PolicyRule
		setURL       bool
		wantFailed   bool
		wantRequests []string
	}{
		{name: "released metadata filters out the URL", rule: releasedRule, setURL: true, wantFailed: true},
		{name: "declared input, unset", rule: companionRule, setURL: false, wantFailed: true},
		{
			name:         "declared input, set",
			rule:         companionRule,
			setURL:       true,
			wantFailed:   false,
			wantRequests: []string{"POST /api/v1/log/entries/retrieve"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rekor, requests := fakeRekor(t, response)
			sessionObj := cautils.NewOPASessionObjMock()
			sessionObj.RegoInputData.PostureControlInputs = map[string][]string{"trustedCosignPublicKeys": {key}}
			if tt.setURL {
				sessionObj.RegoInputData.PostureControlInputs[cosignRekorURLInput] = []string{rekor.URL}
			}
			proc := NewOPAProcessor(sessionObj, &resources.RegoDependenciesData{}, "", "", "", false, nil)

			responses, err := proc.EvaluateRule(context.Background(), tt.rule, []workloadinterface.IMetadata{pod}, "C-0236")
			require.NoError(t, err)
			if tt.wantFailed {
				assert.Len(t, responses, 1, "a signature with no Rekor entry looked up must fail")
			} else {
				assert.Empty(t, responses, "the image logged in the configured Rekor must pass")
			}
			assert.Equal(t, tt.wantRequests, *requests, "requests to the configured Rekor")
		})
	}
}
