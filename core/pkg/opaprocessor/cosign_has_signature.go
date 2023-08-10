package opaprocessor

import (
	"context"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/sigstore/cosign/v2/pkg/cosign"
)

func has_signature(img string) bool {
	ref, err := name.ParseReference(img)
	if err != nil {
		return false
	}
	sins, err := cosign.FetchSignaturesForReference(context.Background(), ref)

	if err != nil {
		return false
	}

	return len(sins) > 0
}
