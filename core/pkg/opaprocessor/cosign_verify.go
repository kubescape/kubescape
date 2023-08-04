package opaprocessor

import (
	"context"
	"crypto"
	"fmt"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/sign"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/sigstore/cosign/v2/pkg/cosign/pkcs11key"
	ociremote "github.com/sigstore/cosign/v2/pkg/oci/remote"
	sigs "github.com/sigstore/cosign/v2/pkg/signature"
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

// Exec runs the verification command
func verify(img string, key string) (bool, error) {

	co := &cosign.CheckOpts{}
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

	_, _, err = cosign.VerifyImageSignatures(context.TODO(), ref, co)
	if err != nil {
		return false, fmt.Errorf("verifying signature: %w", err)
	}

	return true, nil
}
