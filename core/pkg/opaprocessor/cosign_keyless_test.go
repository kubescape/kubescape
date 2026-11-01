package opaprocessor

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	ct "github.com/google/certificate-transparency-go"
	cttls "github.com/google/certificate-transparency-go/tls"
	ctx509 "github.com/google/certificate-transparency-go/x509"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/resources"
	"github.com/sigstore/cosign/v3/pkg/cosign"
	"github.com/sigstore/cosign/v3/pkg/oci"
	"github.com/sigstore/cosign/v3/pkg/oci/static"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testIssuer   = "https://token.actions.githubusercontent.com"
	testIdentity = "https://github.com/acme/app/.github/workflows/release.yml@refs/heads/main"
)

// fakeFulcio is a Fulcio CA and CT log for keyless signatures.
type fakeFulcio struct {
	root    *x509.Certificate
	rootKey *ecdsa.PrivateKey
	ctKey   *ecdsa.PrivateKey
	ctPub   string
}

var (
	trustedFulcioOnce sync.Once
	trustedFulcio     *fakeFulcio
)

// trustedFakeFulcio returns the CA cosign trusts in these tests. cosign reads
// SIGSTORE_ROOT_FILE once per process, so every test shares this one CA.
func trustedFakeFulcio(t *testing.T) *fakeFulcio {
	t.Helper()
	trustedFulcioOnce.Do(func() {
		dir, err := os.MkdirTemp("", "fulcio")
		require.NoError(t, err)
		trustedFulcio = newFakeFulcio(t, dir)
		rootFile := filepath.Join(dir, "root.pem")
		require.NoError(t, os.WriteFile(rootFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: trustedFulcio.root.Raw}), 0o600))
		require.NoError(t, os.Setenv("SIGSTORE_ROOT_FILE", rootFile))
	})
	t.Setenv("SIGSTORE_CT_LOG_PUBLIC_KEY_FILE", trustedFulcio.ctPub)
	return trustedFulcio
}

func newFakeFulcio(t *testing.T, dir string) *fakeFulcio {
	t.Helper()
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "fake fulcio"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &rootKey.PublicKey, rootKey)
	require.NoError(t, err)
	root, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	ctKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ctPub, err := os.CreateTemp(dir, "ctlog-*.pub")
	require.NoError(t, err)
	_, err = ctPub.Write(publicKeyPEM(t, &ctKey.PublicKey))
	require.NoError(t, err)
	require.NoError(t, ctPub.Close())
	return &fakeFulcio{root: root, rootKey: rootKey, ctKey: ctKey, ctPub: ctPub.Name()}
}

// issue returns a signing certificate for identity and issuer, as Fulcio
// issues it: with an embedded SCT from the CT log, unless withSCT is false.
func (f *fakeFulcio) issue(t *testing.T, signer *ecdsa.PrivateKey, identity, issuer string, withSCT bool) *x509.Certificate {
	t.Helper()
	san, err := url.Parse(identity)
	require.NoError(t, err)
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		URIs:         []*url.URL{san},
		ExtraExtensions: []pkix.Extension{
			{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 1}, Value: []byte(issuer)},
		},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, f.root, &signer.PublicKey, f.rootKey)
	require.NoError(t, err)
	if withSCT {
		tbs, err := x509.ParseCertificate(der)
		require.NoError(t, err)
		tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, f.sctExtension(t, tbs.RawTBSCertificate))
		der, err = x509.CreateCertificate(rand.Reader, tmpl, f.root, &signer.PublicKey, f.rootKey)
		require.NoError(t, err)
	}
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

// sctExtension returns the embedded SCT list extension for a certificate whose
// TBSCertificate, without that extension, is tbs.
func (f *fakeFulcio) sctExtension(t *testing.T, tbs []byte) pkix.Extension {
	t.Helper()
	pubDER, err := x509.MarshalPKIXPublicKey(&f.ctKey.PublicKey)
	require.NoError(t, err)
	sct := ct.SignedCertificateTimestamp{
		SCTVersion: ct.V1,
		LogID:      ct.LogID{KeyID: sha256.Sum256(pubDER)},
		Timestamp:  uint64(time.Now().UnixMilli()),
	}
	entry := ct.LogEntry{Leaf: ct.MerkleTreeLeaf{
		Version:  ct.V1,
		LeafType: ct.TimestampedEntryLeafType,
		TimestampedEntry: &ct.TimestampedEntry{
			EntryType: ct.PrecertLogEntryType,
			Timestamp: sct.Timestamp,
			PrecertEntry: &ct.PreCert{
				IssuerKeyHash:  sha256.Sum256(f.root.RawSubjectPublicKeyInfo),
				TBSCertificate: tbs,
			},
		},
	}}
	input, err := ct.SerializeSCTSignatureInput(sct, entry)
	require.NoError(t, err)
	signed, err := cttls.CreateSignature(*f.ctKey, cttls.SHA256, input)
	require.NoError(t, err)
	sct.Signature = ct.DigitallySigned(signed)
	sctBytes, err := cttls.Marshal(sct)
	require.NoError(t, err)
	list, err := cttls.Marshal(ctx509.SignedCertificateTimestampList{SCTList: []ctx509.SerializedSCT{{Val: sctBytes}}})
	require.NoError(t, err)
	value, err := asn1.Marshal(list)
	require.NoError(t, err)
	return pkix.Extension{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}, Value: value}
}

// signKeyless signs a payload naming img with a fresh key and attaches the
// certificate f issued for it, as `cosign sign` stores a keyless signature
// with --tlog-upload=false.
func (f *fakeFulcio) signKeyless(t *testing.T, img name.Digest, identity, issuer string, withSCT bool) oci.Signature {
	t.Helper()
	signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	unbundled := signImageDigestWithoutBundle(t, signer, img)
	payload, err := unbundled.Payload()
	require.NoError(t, err)
	b64Sig, err := unbundled.Base64Signature()
	require.NoError(t, err)
	cert := f.issue(t, signer, identity, issuer, withSCT)
	sig, err := static.NewSignature(payload, b64Sig, static.WithCertChain(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.root.Raw}),
	))
	require.NoError(t, err)
	return sig
}

func TestWithCosignPolicy_TrustedIdentities(t *testing.T) {
	tests := []struct {
		name    string
		entries []string
		want    []cosign.Identity
	}{
		{name: "absent", entries: nil, want: nil},
		{name: "issuer only is ignored", entries: []string{testIssuer}, want: nil},
		{name: "blank is ignored", entries: []string{"  "}, want: nil},
		{
			name:    "issuer and identity",
			entries: []string{"^https://token\\.actions\\.githubusercontent\\.com$ ^https://github\\.com/acme/.*$"},
			want:    []cosign.Identity{{IssuerRegExp: "^https://token\\.actions\\.githubusercontent\\.com$", SubjectRegExp: "^https://github\\.com/acme/.*$"}},
		},
		{
			name:    "identity keeps its spaces",
			entries: []string{" https://issuer.example\t ^build bot <ci@example.com>$ "},
			want:    []cosign.Identity{{IssuerRegExp: "https://issuer.example", SubjectRegExp: "^build bot <ci@example.com>$"}},
		},
		{
			name:    "invalid expression is ignored",
			entries: []string{"( b", "a [", "c d"},
			want:    []cosign.Identity{{IssuerRegExp: "c", SubjectRegExp: "d"}},
		},
		{
			name:    "several",
			entries: []string{"a b", "c", "d e"},
			want:    []cosign.Identity{{IssuerRegExp: "a", SubjectRegExp: "b"}, {IssuerRegExp: "d", SubjectRegExp: "e"}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inputs := map[string][]string{}
			if tt.entries != nil {
				inputs[trustedCosignIdentitiesInput] = tt.entries
			}
			ctx := withCosignPolicy(context.Background(), inputs)
			assert.Equal(t, tt.want, cosignPolicyFrom(ctx).identities)
		})
	}
}

// TestVerifyKeyless covers cosign.verify_keyless: a keyless signature passes
// only when its certificate chains to the Fulcio root, carries an SCT from the
// CT log, names a trusted issuer and identity, and signs the image verified.
func TestVerifyKeyless(t *testing.T) {
	fulcio := trustedFakeFulcio(t)
	untrusted := newFakeFulcio(t, t.TempDir())
	server := httptest.NewServer(registry.New(registry.Logger(log.New(io.Discard, "", 0))))
	t.Cleanup(server.Close)
	repo := strings.TrimPrefix(server.URL, "http://")
	trusted := []string{"^" + testIssuer + "$ ^https://github\\.com/acme/"}

	signed := func(f *fakeFulcio, identity, issuer string, withSCT bool) string {
		img := pushRandomImage(t, repo+"/test/keyless")
		attachSignature(t, img, f.signKeyless(t, img, identity, issuer, withSCT))
		return img.String()
	}
	otherImage := func() string {
		img := pushRandomImage(t, repo+"/test/keyless")
		other := pushRandomImage(t, repo+"/test/other")
		attachSignature(t, other, fulcio.signKeyless(t, img, testIdentity, testIssuer, true))
		return other.String()
	}

	tests := []struct {
		name    string
		img     string
		inputs  map[string][]string
		wantErr string
	}{
		{
			name:   "trusted identity",
			img:    signed(fulcio, testIdentity, testIssuer, true),
			inputs: map[string][]string{trustedCosignIdentitiesInput: trusted, cosignRequireTransparencyLogInput: {"false"}},
		},
		{
			name:   "trusted identity after an invalid entry",
			img:    signed(fulcio, testIdentity, testIssuer, true),
			inputs: map[string][]string{trustedCosignIdentitiesInput: append([]string{"( ^https://github\\.com/acme/"}, trusted...), cosignRequireTransparencyLogInput: {"false"}},
		},
		{
			name:    "no identities configured",
			img:     signed(fulcio, testIdentity, testIssuer, true),
			inputs:  map[string][]string{cosignRequireTransparencyLogInput: {"false"}},
			wantErr: "no trusted cosign identities configured",
		},
		{
			name:    "untrusted identity",
			img:     signed(fulcio, "https://github.com/mallory/app/.github/workflows/release.yml@refs/heads/main", testIssuer, true),
			inputs:  map[string][]string{trustedCosignIdentitiesInput: trusted, cosignRequireTransparencyLogInput: {"false"}},
			wantErr: "none of the expected identities matched",
		},
		{
			name:    "untrusted issuer",
			img:     signed(fulcio, testIdentity, "https://accounts.example.com", true),
			inputs:  map[string][]string{trustedCosignIdentitiesInput: trusted, cosignRequireTransparencyLogInput: {"false"}},
			wantErr: "none of the expected identities matched",
		},
		{
			name:    "certificate from another CA",
			img:     signed(untrusted, testIdentity, testIssuer, true),
			inputs:  map[string][]string{trustedCosignIdentitiesInput: trusted, cosignRequireTransparencyLogInput: {"false"}},
			wantErr: "certificate signed by unknown authority",
		},
		{
			name:    "no SCT",
			img:     signed(fulcio, testIdentity, testIssuer, false),
			inputs:  map[string][]string{trustedCosignIdentitiesInput: trusted, cosignRequireTransparencyLogInput: {"false"}},
			wantErr: "certificate does not include required embedded SCT",
		},
		{
			name:    "SCT from another CT log",
			img:     signed(&fakeFulcio{root: fulcio.root, rootKey: fulcio.rootKey, ctKey: untrusted.ctKey}, testIdentity, testIssuer, true),
			inputs:  map[string][]string{trustedCosignIdentitiesInput: trusted, cosignRequireTransparencyLogInput: {"false"}},
			wantErr: "ctfe public key not found",
		},
		{
			name:    "signature for another image",
			img:     otherImage(),
			inputs:  map[string][]string{trustedCosignIdentitiesInput: trusted, cosignRequireTransparencyLogInput: {"false"}},
			wantErr: "invalid or missing digest in claim",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ok, err := verifyKeyless(withCosignPolicy(context.Background(), tt.inputs), tt.img)
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

// TestVerifyKeyless_RequiresTransparencyLogByDefault checks the keyless path
// keeps the tlog requirement: a signature with no Rekor bundle fails unless
// cosignRequireTransparencyLog is false.
func TestVerifyKeyless_RequiresTransparencyLogByDefault(t *testing.T) {
	fulcio := trustedFakeFulcio(t)
	logKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	rekorPub := filepath.Join(t.TempDir(), "rekor.pub")
	require.NoError(t, os.WriteFile(rekorPub, publicKeyPEM(t, &logKey.PublicKey), 0o600))
	t.Setenv("SIGSTORE_REKOR_PUBLIC_KEY", rekorPub)

	server := httptest.NewServer(registry.New(registry.Logger(log.New(io.Discard, "", 0))))
	t.Cleanup(server.Close)
	img := pushRandomImage(t, strings.TrimPrefix(server.URL, "http://")+"/test/keyless")
	attachSignature(t, img, fulcio.signKeyless(t, img, testIdentity, testIssuer, true))

	ctx := withCosignPolicy(context.Background(), map[string][]string{trustedCosignIdentitiesInput: {testIssuer + " " + testIdentity}})
	ok, err := verifyKeyless(ctx, img.String())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "rekor client not provided for online verification")
	assert.False(t, ok)
}

// verifyImageSignatureKeylessRego is regolibrary's verify-image-signature rule
// with the keyless check, cut down to bare Pods.
const verifyImageSignatureKeylessRego = `package armo_builtins
import rego.v1

deny contains msga if {
	pod := input[_]
	pod.kind == "Pod"
	container := pod.spec.containers[i]
	verified_keys := [trusted_key | trusted_key = data.postureControlInputs.trustedCosignPublicKeys[_]; cosign.verify(container.image, trusted_key)]
	count(verified_keys) == 0
	not cosign.verify_keyless(container.image)
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

const trustedIdentitiesInput = `{
	"path": "settings.postureControlInputs.trustedCosignIdentities",
	"name": "Trusted Cosign keyless identities",
	"description": "Keyless signers to trust: an OIDC issuer regular expression, whitespace, then a certificate identity regular expression."
}`

// TestEvaluateRule_TrustedCosignIdentitiesNeedRuleMetadata runs the scan path
// from rule metadata: trustedCosignIdentities reaches cosign.verify_keyless
// only when the rule declares it, and then a keyless-signed image passes.
func TestEvaluateRule_TrustedCosignIdentitiesNeedRuleMetadata(t *testing.T) {
	fulcio := trustedFakeFulcio(t)
	server := httptest.NewServer(registry.New(registry.Logger(log.New(io.Discard, "", 0))))
	t.Cleanup(server.Close)
	img := pushRandomImage(t, strings.TrimPrefix(server.URL, "http://")+"/test/keyless")
	attachSignature(t, img, fulcio.signKeyless(t, img, testIdentity, testIssuer, true))
	pod := podWithImage(img)

	rule := func(configInputs ...string) *reporthandling.PolicyRule {
		r := verifyImageSignatureRule(t, configInputs...)
		r.Rule = verifyImageSignatureKeylessRego
		return r
	}
	releasedRule := rule(trustedKeysInput, requireTlogInput, rekorURLInput)
	companionRule := rule(trustedKeysInput, requireTlogInput, rekorURLInput, trustedIdentitiesInput)

	tests := []struct {
		name       string
		rule       *reporthandling.PolicyRule
		identities []string
		wantFailed bool
	}{
		{name: "released metadata filters out the identities", rule: releasedRule, identities: []string{testIssuer + " " + testIdentity}, wantFailed: true},
		{name: "declared input, unset", rule: companionRule, wantFailed: true},
		{name: "declared input, other identity", rule: companionRule, identities: []string{testIssuer + " ^https://github\\.com/other/"}, wantFailed: true},
		{name: "declared input, trusted identity", rule: companionRule, identities: []string{testIssuer + " " + testIdentity}, wantFailed: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sessionObj := cautils.NewOPASessionObjMock()
			sessionObj.RegoInputData.PostureControlInputs = map[string][]string{
				"trustedCosignPublicKeys":         {},
				cosignRequireTransparencyLogInput: {"false"},
			}
			if tt.identities != nil {
				sessionObj.RegoInputData.PostureControlInputs[trustedCosignIdentitiesInput] = tt.identities
			}
			proc := NewOPAProcessor(sessionObj, &resources.RegoDependenciesData{}, "", "", "", false, nil)

			responses, err := proc.EvaluateRule(context.Background(), tt.rule, []workloadinterface.IMetadata{pod}, "C-0236")
			require.NoError(t, err)
			if tt.wantFailed {
				assert.Len(t, responses, 1, fmt.Sprintf("image %s must fail", img))
			} else {
				assert.Empty(t, responses, "the keyless-signed image must pass")
			}
		})
	}
}
