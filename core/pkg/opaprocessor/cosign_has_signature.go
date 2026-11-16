package opaprocessor

import (
	"context"
	"encoding/json"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/sigstore/cosign/v3/pkg/cosign"
	ociremote "github.com/sigstore/cosign/v3/pkg/oci/remote"
	"github.com/sigstore/cosign/v3/pkg/types"
)

func has_signature(ctx context.Context, img string) bool {
	if ctx.Err() != nil {
		return false
	}
	ref, err := name.ParseReference(img)
	if err != nil {
		return false
	}
	opts := []ociremote.Option{ociremote.WithMoreRemoteOptions(remote.WithContext(ctx))}
	entity, err := ociremote.SignedEntity(ref, opts...)
	if err != nil {
		return false
	}
	if sigs, err := cosign.FetchSignatures(entity); err == nil && len(sigs) > 0 {
		return true
	}
	if ctx.Err() != nil {
		return false
	}
	digest, err := entity.Digest()
	if err != nil {
		return false
	}
	return hasSignatureBundle(ctx, ref.Context().Digest(digest.String()), digest, opts)
}

func hasSignatureBundle(ctx context.Context, ref name.Digest, digest v1.Hash, opts []ociremote.Option) bool {
	bundles, _, err := cosign.GetBundles(ctx, ref, opts)
	if err != nil {
		return false
	}
	for _, bundle := range bundles {
		envelope := bundle.GetDsseEnvelope()
		if !isCosignSignStatement(envelope.GetPayload(), digest) {
			continue
		}
		for _, signature := range envelope.GetSignatures() {
			if len(signature.GetSig()) > 0 {
				return true
			}
		}
	}
	return false
}

func isCosignSignStatement(statement []byte, digest v1.Hash) bool {
	var parsed struct {
		PredicateType string `json:"predicateType"`
		Subject       []struct {
			Digest map[string]string `json:"digest"`
		} `json:"subject"`
	}
	if err := json.Unmarshal(statement, &parsed); err != nil || parsed.PredicateType != types.CosignSignPredicateType {
		return false
	}
	for _, subject := range parsed.Subject {
		if subject.Digest[digest.Algorithm] == digest.Hex {
			return true
		}
	}
	return false
}
