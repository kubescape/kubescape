package opaprocessor

import (
	"context"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/sigstore/cosign/pkg/cosign"
)


func has_signature(img string) bool {
	ref, err := name.ParseReference(img)
	if err != nil {
		logger.L().Error("parsing reference", helpers.Error(err))
		return false
	}
	sins, err := cosign.FetchSignaturesForReference(context.Background(), ref)

	if err != nil {
		logger.L().Error("verifying signature", helpers.Error(err))
		return false

	}

	return len(sins) > 0
}
