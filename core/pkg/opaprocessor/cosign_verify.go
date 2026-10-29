package opaprocessor

import (
	"context"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"unicode"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/fulcio"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/rekor"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/sign"
	"github.com/sigstore/cosign/v3/pkg/cosign"
	"github.com/sigstore/cosign/v3/pkg/cosign/pkcs11key"
	"github.com/sigstore/cosign/v3/pkg/oci"
	ociremote "github.com/sigstore/cosign/v3/pkg/oci/remote"
	sigs "github.com/sigstore/cosign/v3/pkg/signature"
	"github.com/sigstore/cosign/v3/pkg/types"
	"github.com/sigstore/sigstore-go/pkg/root"
)

// VerifyCommand verifies a signature on a supplied container image
type VerifyCommand struct {
	options.RegistryOptions
	Annotations                  sigs.AnnotationsMap
	CertChain                    string
	CertEmail                    string
	CertOidcProvider             string
	CertIdentity                 string
	CertOidcIssuer               string
	CertGithubWorkflowTrigger    string
	CertGithubWorkflowSha        string
	CertGithubWorkflowName       string
	KeyRef                       string
	CertGithubWorkflowRef        string
	SignatureRef                 string
	CertRef                      string
	CertGithubWorkflowRepository string
	Attachment                   string
	Slot                         string
	Output                       string
	RekorURL                     string
	HashAlgorithm                crypto.Hash
	Sk                           bool
	CheckClaims                  bool
	LocalImage                   bool
	EnforceSCT                   bool
}

// cosignRequireTransparencyLogInput is the posture control input that decides
// whether cosign.verify requires a transparency log (Rekor) entry. Setting it
// to "false" behaves like `cosign verify --insecure-ignore-tlog`, for images
// signed with --tlog-upload=false in private registries and air-gapped
// clusters. Any other value, or no value, keeps the entry required.
const cosignRequireTransparencyLogInput = "cosignRequireTransparencyLog"

// cosignRekorURLInput is the posture control input that sets the Rekor
// instance cosign.verify looks up signatures without a Rekor bundle in, like
// `cosign verify --rekor-url`. No value keeps today's behaviour.
const cosignRekorURLInput = "cosignRekorURL"

// trustedCosignIdentitiesInput is the posture control input that lists the
// keyless (Fulcio) signers cosign.verify_keyless trusts. Each entry is an OIDC
// issuer regular expression, whitespace, and a certificate identity regular
// expression, like `cosign verify --certificate-oidc-issuer-regexp
// --certificate-identity-regexp`. The issuer ends at the first whitespace, so
// the identity may itself contain spaces. The expressions are not anchored.
const trustedCosignIdentitiesInput = "trustedCosignIdentities"

type cosignPolicyKey struct{}

type cosignPolicy struct {
	ignoreTlog bool
	rekorURL   string
	identities []cosign.Identity
}

// withCosignPolicy returns ctx carrying the cosign verification policy read
// from a rule's posture control inputs. cosign.verify is a process-global Rego
// builtin, so the evaluation context is how a per-rule setting reaches it.
func withCosignPolicy(ctx context.Context, postureControlInputs map[string][]string) context.Context {
	var policy cosignPolicy
	if values := postureControlInputs[cosignRequireTransparencyLogInput]; len(values) > 0 {
		policy.ignoreTlog = strings.EqualFold(strings.TrimSpace(values[0]), "false")
	}
	if values := postureControlInputs[cosignRekorURLInput]; len(values) > 0 {
		policy.rekorURL = strings.TrimSpace(values[0])
	}
	for _, entry := range postureControlInputs[trustedCosignIdentitiesInput] {
		if identity, ok := parseCosignIdentity(entry); ok {
			policy.identities = append(policy.identities, identity)
		}
	}
	if !policy.ignoreTlog && policy.rekorURL == "" && len(policy.identities) == 0 {
		return ctx
	}
	return context.WithValue(ctx, cosignPolicyKey{}, policy)
}

// parseCosignIdentity splits a trustedCosignIdentities entry into its issuer
// and identity expressions. An entry without both, or with an expression that
// does not compile, is ignored: cosign stops at the first invalid expression,
// so it would otherwise hide the entries after it.
func parseCosignIdentity(entry string) (cosign.Identity, bool) {
	entry = strings.TrimSpace(entry)
	i := strings.IndexFunc(entry, unicode.IsSpace)
	if i < 0 {
		return cosign.Identity{}, false
	}
	issuer, subject := entry[:i], strings.TrimSpace(entry[i:])
	if subject == "" {
		return cosign.Identity{}, false
	}
	if _, err := regexp.Compile(issuer); err != nil {
		return cosign.Identity{}, false
	}
	if _, err := regexp.Compile(subject); err != nil {
		return cosign.Identity{}, false
	}
	return cosign.Identity{IssuerRegExp: issuer, SubjectRegExp: subject}, true
}

func cosignPolicyFrom(ctx context.Context) cosignPolicy {
	policy, _ := ctx.Value(cosignPolicyKey{}).(cosignPolicy)
	return policy
}

// Exec runs the verification command
func verify(ctx context.Context, img string, key string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, fmt.Errorf("context canceled before verification: %w", err)
	}
	co := &cosign.CheckOpts{
		// Require the signed payload to name the digest being verified,
		// matching the claim check `cosign verify` performs by default.
		ClaimVerifier: cosign.SimpleClaimVerifier,
	}

	pubKey, err := sigs.LoadPublicKeyRaw([]byte(key), crypto.SHA256)
	if err != nil {
		return false, fmt.Errorf("loading public key: %w", err)
	}
	pkcs11Key, ok := pubKey.(*pkcs11key.Key)
	if ok {
		defer pkcs11Key.Close()
	}
	co.SigVerifier = pubKey
	return verifyImageSignatures(ctx, img, co)
}

// verifyKeyless verifies img against the Fulcio certificate on its signature:
// the certificate must chain to the Fulcio roots, carry a valid SCT, and name
// an issuer and identity from trustedCosignIdentities.
func verifyKeyless(ctx context.Context, img string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, fmt.Errorf("context canceled before verification: %w", err)
	}
	policy := cosignPolicyFrom(ctx)
	if len(policy.identities) == 0 {
		return false, errors.New("no trusted cosign identities configured")
	}
	co := &cosign.CheckOpts{
		ClaimVerifier: cosign.SimpleClaimVerifier,
		Identities:    policy.identities,
	}
	return verifyImageSignatures(ctx, img, co)
}

// cosignTrustedRoot returns the Sigstore trusted root that signatures in the
// Sigstore bundle format are verified against.
var cosignTrustedRoot = sync.OnceValues(cosign.TrustedRoot)

// verifyImageSignatures verifies img with co, whether it was signed in the
// Sigstore bundle format that `cosign sign` writes by default since v3, or in
// the legacy format. Bundles are tried first when the image has any; as they
// include attestations and other signers' bundles, the legacy signature is
// still checked when none of them verifies.
func verifyImageSignatures(ctx context.Context, img string, co *cosign.CheckOpts) (bool, error) {
	var ociremoteOpts []ociremote.Option
	attachment := ""

	ref, err := name.ParseReference(img)
	if err != nil {
		return false, fmt.Errorf("parsing reference: %w", err)
	}
	ref, err = sign.GetAttachedImageRef(ref, attachment, ociremoteOpts...)
	if err != nil {
		return false, fmt.Errorf("resolving attachment type %s for image %s: %w", attachment, img, err)
	}
	bundles, _, err := cosign.GetBundles(ctx, ref, co.RegistryClientOpts)
	if err != nil || len(bundles) == 0 {
		return verifyLegacySignatures(ctx, ref, co)
	}
	bundleOpts := *co
	if ok, bundleErr := verifySigstoreBundles(ctx, ref, &bundleOpts); ok {
		return true, nil
	} else if ok, legacyErr := verifyLegacySignatures(ctx, ref, co); ok {
		return true, nil
	} else {
		return false, errors.Join(bundleErr, legacyErr)
	}
}

// verifySigstoreBundles verifies the Sigstore bundles attached to ref. Only
// bundles holding a `cosign sign` statement count, so an attestation of
// another predicate type signed by the same identity is not a signature.
func verifySigstoreBundles(ctx context.Context, ref name.Reference, co *cosign.CheckOpts) (bool, error) {
	co.NewBundleFormat = true
	co.ClaimVerifier = cosignSignClaimVerifier
	if cosignPolicyFrom(ctx).ignoreTlog {
		co.IgnoreTlog = true
	}
	if co.SigVerifier != nil && co.IgnoreTlog {
		// A key and no transparency log need no Sigstore trust material, so
		// an air-gapped cluster does not fetch it.
		co.TrustedMaterial = &root.BaseTrustedMaterial{}
	} else {
		trustedRoot, err := cosignTrustedRoot()
		if err != nil {
			return false, fmt.Errorf("getting Sigstore trusted root: %w", err)
		}
		co.TrustedMaterial = trustedRoot
	}
	if err := ctx.Err(); err != nil {
		return false, fmt.Errorf("context canceled before signature verification: %w", err)
	}

	if co.SigVerifier != nil {
		if _, _, err := cosign.VerifyImageAttestations(ctx, ref, co); err != nil {
			return false, fmt.Errorf("verifying bundle: %w", err)
		}
		return true, nil
	}
	// cosign verifies a bundle against one identity at a time.
	var errs []error
	for _, identity := range co.Identities {
		identityOpts := *co
		identityOpts.Identities = []cosign.Identity{identity}
		_, _, err := cosign.VerifyImageAttestations(ctx, ref, &identityOpts)
		if err == nil {
			return true, nil
		}
		errs = append(errs, err)
	}
	return false, fmt.Errorf("verifying bundle: %w", errors.Join(errs...))
}

// cosignSignClaimVerifier accepts a bundle statement that names the image
// digest and has the predicate type `cosign sign` writes.
func cosignSignClaimVerifier(sig oci.Signature, imageDigest v1.Hash, annotations map[string]any) error {
	if err := cosign.IntotoSubjectClaimVerifier(sig, imageDigest, annotations); err != nil {
		return err
	}
	payload, err := sig.Payload()
	if err != nil {
		return err
	}
	var envelope dsse.Envelope
	if err := json.Unmarshal(payload, &envelope); err != nil {
		return err
	}
	statement, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil {
		return err
	}
	var header struct {
		PredicateType string `json:"predicateType"`
	}
	if err := json.Unmarshal(statement, &header); err != nil {
		return err
	}
	if header.PredicateType != types.CosignSignPredicateType {
		return fmt.Errorf("bundle predicate type %q is not a cosign signature", header.PredicateType)
	}
	return nil
}

func verifyLegacySignatures(ctx context.Context, ref name.Reference, co *cosign.CheckOpts) (bool, error) {
	var err error
	if co.SigVerifier == nil {
		if co.RootCerts, err = fulcio.GetRoots(); err != nil {
			return false, fmt.Errorf("getting Fulcio roots: %w", err)
		}
		if co.IntermediateCerts, err = fulcio.GetIntermediates(); err != nil {
			return false, fmt.Errorf("getting Fulcio intermediates: %w", err)
		}
		if co.CTLogPubKeys, err = cosign.GetCTLogPubs(ctx); err != nil {
			return false, fmt.Errorf("getting CT log public keys: %w", err)
		}
	}
	policy := cosignPolicyFrom(ctx)
	if policy.ignoreTlog {
		// No Rekor keys are needed, so an air-gapped cluster does not fail on
		// fetching them either.
		co.IgnoreTlog = true
	} else {
		if err := ctx.Err(); err != nil {
			return false, fmt.Errorf("context canceled before Rekor public key retrieval: %w", err)
		}

		if policy.rekorURL != "" {
			co.RekorClient, err = rekor.NewClient(policy.rekorURL)
			if err != nil {
				return false, fmt.Errorf("creating Rekor client: %w", err)
			}
		}

		co.RekorPubKeys, err = cosign.GetRekorPubs(ctx)
		if err != nil {
			return false, fmt.Errorf("getting Rekor public keys: %w", err)
		}
	}
	if err := ctx.Err(); err != nil {
		return false, fmt.Errorf("context canceled before signature verification: %w", err)
	}

	_, _, err = cosign.VerifyImageSignatures(ctx, ref, co)
	if err != nil {
		return false, fmt.Errorf("verifying signature: %w", err)
	}

	return true, nil
}
