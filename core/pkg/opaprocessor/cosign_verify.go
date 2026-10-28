package opaprocessor

import (
	"context"
	"crypto"
	"fmt"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/rekor"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/sign"
	"github.com/sigstore/cosign/v3/pkg/cosign"
	"github.com/sigstore/cosign/v3/pkg/cosign/pkcs11key"
	ociremote "github.com/sigstore/cosign/v3/pkg/oci/remote"
	sigs "github.com/sigstore/cosign/v3/pkg/signature"
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

type cosignPolicyKey struct{}

type cosignPolicy struct {
	ignoreTlog bool
	rekorURL   string
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
	if policy == (cosignPolicy{}) {
		return ctx
	}
	return context.WithValue(ctx, cosignPolicyKey{}, policy)
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
	var ociremoteOpts []ociremote.Option
	attachment := ""

	pubKey, err := sigs.LoadPublicKeyRaw([]byte(key), crypto.SHA256)
	if err != nil {
		return false, fmt.Errorf("loading public key: %w", err)
	}
	pkcs11Key, ok := pubKey.(*pkcs11key.Key)
	if ok {
		defer pkcs11Key.Close()
	}
	co.SigVerifier = pubKey
	ref, err := name.ParseReference(img)
	if err != nil {
		return false, fmt.Errorf("parsing reference: %w", err)
	}
	ref, err = sign.GetAttachedImageRef(ref, attachment, ociremoteOpts...)
	if err != nil {
		return false, fmt.Errorf("resolving attachment type %s for image %s: %w", attachment, img, err)
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
