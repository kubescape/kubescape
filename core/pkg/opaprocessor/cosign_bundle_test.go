package opaprocessor

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	ociremote "github.com/sigstore/cosign/v3/pkg/oci/remote"
	"github.com/sigstore/cosign/v3/pkg/types"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	protodsse "github.com/sigstore/protobuf-specs/gen/pb-go/dsse"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
)

// trustedRoot returns a Sigstore trusted root holding f's CA and CT log.
func (f *fakeFulcio) trustedRoot(t *testing.T) root.TrustedMaterial {
	t.Helper()
	pubDER, err := x509.MarshalPKIXPublicKey(&f.ctKey.PublicKey)
	require.NoError(t, err)
	logID := sha256.Sum256(pubDER)
	tr, err := root.NewTrustedRoot(root.TrustedRootMediaType01,
		[]root.CertificateAuthority{&root.FulcioCertificateAuthority{Root: f.root}},
		map[string]*root.TransparencyLog{hex.EncodeToString(logID[:]): {
			ID:                logID[:],
			PublicKey:         &f.ctKey.PublicKey,
			HashFunc:          crypto.SHA256,
			SignatureHashFunc: crypto.SHA256,
		}},
		nil, nil)
	require.NoError(t, err)
	return tr
}

func useTrustedRoot(t *testing.T, tm root.TrustedMaterial) {
	t.Helper()
	previous := cosignTrustedRoot
	cosignTrustedRoot = func() (root.TrustedMaterial, error) { return tm, nil }
	t.Cleanup(func() { cosignTrustedRoot = previous })
}

// attachBundle signs an in-toto statement about subject with signer and
// attaches it to img as a Sigstore bundle, as `cosign sign` does by default
// since v3 with --tlog-upload=false. A nil cert makes it a key-signed bundle.
func attachBundle(t *testing.T, img, subject name.Digest, signer *ecdsa.PrivateKey, cert *x509.Certificate, predicateType string) {
	t.Helper()
	statement := []byte(fmt.Sprintf(
		`{"_type":"https://in-toto.io/Statement/v1","subject":[{"name":%q,"digest":{"sha256":%q}}],"predicateType":%q,"predicate":{}}`,
		subject.Context().String(), strings.TrimPrefix(subject.DigestStr(), "sha256:"), predicateType))
	pae := sha256.Sum256(dsse.PAE("application/vnd.in-toto+json", statement))
	sig, err := ecdsa.SignASN1(rand.Reader, signer, pae[:])
	require.NoError(t, err)

	material := &protobundle.VerificationMaterial{}
	if cert != nil {
		material.Content = &protobundle.VerificationMaterial_Certificate{Certificate: &protocommon.X509Certificate{RawBytes: cert.Raw}}
	} else {
		material.Content = &protobundle.VerificationMaterial_PublicKey{PublicKey: &protocommon.PublicKeyIdentifier{}}
	}
	bundle, err := protojson.Marshal(&protobundle.Bundle{
		MediaType:            "application/vnd.dev.sigstore.bundle.v0.3+json",
		VerificationMaterial: material,
		Content: &protobundle.Bundle_DsseEnvelope{DsseEnvelope: &protodsse.Envelope{
			Payload:     statement,
			PayloadType: "application/vnd.in-toto+json",
			Signatures:  []*protodsse.Signature{{Sig: sig}},
		}},
	})
	require.NoError(t, err)
	require.NoError(t, ociremote.WriteAttestationNewBundleFormat(img, bundle, types.CosignSignPredicateType))
}

// TestVerify_SigstoreBundle covers images signed in the Sigstore bundle
// format, the `cosign sign` default since v3, for both cosign.verify and
// cosign.verify_keyless.
func TestVerify_SigstoreBundle(t *testing.T) {
	fulcio := trustedFakeFulcio(t)
	useTrustedRoot(t, fulcio.trustedRoot(t))
	// Failed bundles fall back to the legacy path, which must not reach the
	// public Rekor.
	logKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	rekorPub := filepath.Join(t.TempDir(), "rekor.pub")
	require.NoError(t, os.WriteFile(rekorPub, publicKeyPEM(t, &logKey.PublicKey), 0o600))
	t.Setenv("SIGSTORE_REKOR_PUBLIC_KEY", rekorPub)
	untrusted := newFakeFulcio(t, t.TempDir())
	server := httptest.NewServer(registry.New(registry.Logger(log.New(io.Discard, "", 0))))
	t.Cleanup(server.Close)
	repo := strings.TrimPrefix(server.URL, "http://")

	keyless := func(f *fakeFulcio, identity, issuer, predicateType string, otherSubject bool) string {
		img := pushRandomImage(t, repo+"/test/bundle")
		subject := img
		if otherSubject {
			subject = pushRandomImage(t, repo+"/test/other")
		}
		signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		attachBundle(t, img, subject, signer, f.issue(t, signer, identity, issuer, true), predicateType)
		return img.String()
	}
	keySigner, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	keySigned := pushRandomImage(t, repo+"/test/bundle")
	attachBundle(t, keySigned, keySigned, keySigner, nil, types.CosignSignPredicateType)
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	noTlog := []string{"false"}
	trusted := []string{"^" + testIssuer + "$ ^https://github\\.com/acme/"}
	tests := []struct {
		name       string
		img        string
		key        *ecdsa.PrivateKey
		identities []string
		tlog       []string
		wantErr    string
	}{
		{name: "keyless, trusted identity", img: keyless(fulcio, testIdentity, testIssuer, types.CosignSignPredicateType, false), identities: trusted, tlog: noTlog},
		{
			name:       "keyless, trusted identity second in the list",
			img:        keyless(fulcio, testIdentity, testIssuer, types.CosignSignPredicateType, false),
			identities: append([]string{testIssuer + " ^https://github\\.com/other/"}, trusted...),
			tlog:       noTlog,
		},
		{
			name:       "keyless, untrusted identity",
			img:        keyless(fulcio, "https://github.com/mallory/app/.github/workflows/release.yml@refs/heads/main", testIssuer, types.CosignSignPredicateType, false),
			identities: trusted,
			tlog:       noTlog,
			wantErr:    "expected SAN value to match regex",
		},
		{
			name:       "keyless, certificate from another CA",
			img:        keyless(untrusted, testIdentity, testIssuer, types.CosignSignPredicateType, false),
			identities: trusted,
			tlog:       noTlog,
			wantErr:    "leaf certificate verification failed",
		},
		{
			name:       "keyless, statement about another image",
			img:        keyless(fulcio, testIdentity, testIssuer, types.CosignSignPredicateType, true),
			identities: trusted,
			tlog:       noTlog,
			wantErr:    "provided artifact digest does not match any digest in statement",
		},
		{
			name:       "keyless, attestation is not a signature",
			img:        keyless(fulcio, testIdentity, testIssuer, "https://slsa.dev/provenance/v1", false),
			identities: trusted,
			tlog:       noTlog,
			wantErr:    "is not a cosign signature",
		},
		{
			name:       "keyless, no transparency log entry while required",
			img:        keyless(fulcio, testIdentity, testIssuer, types.CosignSignPredicateType, false),
			identities: trusted,
			wantErr:    "not enough verified log entries from transparency log",
		},
		{name: "key, trusted key", img: keySigned.String(), key: keySigner, tlog: noTlog},
		{name: "key, another key", img: keySigned.String(), key: otherKey, tlog: noTlog, wantErr: "could not verify envelope"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inputs := map[string][]string{}
			if tt.identities != nil {
				inputs[trustedCosignIdentitiesInput] = tt.identities
			}
			if tt.tlog != nil {
				inputs[cosignRequireTransparencyLogInput] = tt.tlog
			}
			ctx := withCosignPolicy(context.Background(), inputs)
			var ok bool
			var err error
			if tt.key != nil {
				ok, err = verify(ctx, tt.img, string(publicKeyPEM(t, &tt.key.PublicKey)))
			} else {
				ok, err = verifyKeyless(ctx, tt.img)
			}
			if tt.wantErr == "" {
				require.NoError(t, err)
				assert.True(t, ok)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
			assert.False(t, ok)
		})
	}
}

// TestVerify_SigstoreBundleKeyWithoutTlogNeedsNoTrustedRoot checks a
// key-signed bundle verifies without fetching the Sigstore trusted root when
// the transparency log is not required, as in an air-gapped cluster.
func TestVerify_SigstoreBundleKeyWithoutTlogNeedsNoTrustedRoot(t *testing.T) {
	previous := cosignTrustedRoot
	cosignTrustedRoot = func() (root.TrustedMaterial, error) {
		t.Error("the trusted root must not be fetched")
		return nil, fmt.Errorf("offline")
	}
	t.Cleanup(func() { cosignTrustedRoot = previous })
	t.Setenv("SIGSTORE_REKOR_PUBLIC_KEY", filepath.Join(t.TempDir(), "missing.pub"))

	server := httptest.NewServer(registry.New(registry.Logger(log.New(io.Discard, "", 0))))
	t.Cleanup(server.Close)
	img := pushRandomImage(t, strings.TrimPrefix(server.URL, "http://")+"/test/bundle")
	signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	attachBundle(t, img, img, signer, nil, types.CosignSignPredicateType)

	ctx := withCosignPolicy(context.Background(), map[string][]string{cosignRequireTransparencyLogInput: {"false"}})
	ok, err := verify(ctx, img.String(), string(publicKeyPEM(t, &signer.PublicKey)))
	require.NoError(t, err)
	assert.True(t, ok)
}

// TestVerify_LegacySignatureBesideBundle covers images that have a legacy
// signature and Sigstore bundles: when no bundle verifies, the legacy
// signature must still be checked, with its own trust and digest checks.
func TestVerify_LegacySignatureBesideBundle(t *testing.T) {
	fulcio := trustedFakeFulcio(t)
	useTrustedRoot(t, fulcio.trustedRoot(t))
	untrusted := newFakeFulcio(t, t.TempDir())
	server := httptest.NewServer(registry.New(registry.Logger(log.New(io.Discard, "", 0))))
	t.Cleanup(server.Close)
	repo := strings.TrimPrefix(server.URL, "http://")
	noTlog := map[string][]string{cosignRequireTransparencyLogInput: {"false"}}

	t.Run("key signature beside a provenance bundle", func(t *testing.T) {
		signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		img := pushRandomImage(t, repo+"/test/mixed")
		attachSignature(t, img, signImageDigestWithoutBundle(t, signer, img))
		attachBundle(t, img, img, signer, nil, "https://slsa.dev/provenance/v1")

		ok, err := verify(withCosignPolicy(context.Background(), noTlog), img.String(), string(publicKeyPEM(t, &signer.PublicKey)))
		require.NoError(t, err)
		assert.True(t, ok)
	})

	t.Run("keyless signature beside an untrusted bundle", func(t *testing.T) {
		img := pushRandomImage(t, repo+"/test/mixed")
		attachSignature(t, img, fulcio.signKeyless(t, img, testIdentity, testIssuer, true))
		signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		attachBundle(t, img, img, signer, untrusted.issue(t, signer, testIdentity, testIssuer, true), types.CosignSignPredicateType)

		ctx := withCosignPolicy(context.Background(), map[string][]string{
			trustedCosignIdentitiesInput:      {testIssuer + " " + testIdentity},
			cosignRequireTransparencyLogInput: {"false"},
		})
		ok, err := verifyKeyless(ctx, img.String())
		require.NoError(t, err)
		assert.True(t, ok)
	})

	t.Run("legacy signature for another image beside an untrusted bundle", func(t *testing.T) {
		signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		img := pushRandomImage(t, repo+"/test/mixed")
		other := pushRandomImage(t, repo+"/test/other")
		attachSignature(t, img, signImageDigestWithoutBundle(t, signer, other))
		otherSigner, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		attachBundle(t, img, img, otherSigner, nil, types.CosignSignPredicateType)

		ok, err := verify(withCosignPolicy(context.Background(), noTlog), img.String(), string(publicKeyPEM(t, &signer.PublicKey)))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "could not verify envelope", "the bundle failure is reported")
		assert.Contains(t, err.Error(), "invalid or missing digest in claim", "the legacy failure is reported")
		assert.False(t, ok)
	})
}
