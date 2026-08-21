package imagescan

import (
	"context"

	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/openvex/go-vex/pkg/vex"
	"github.com/sigstore/cosign/v3/pkg/cosign"
)

// VexClient interface for fetching VEX documents.
type VexClient interface {
	GetVexStatuses(ctx context.Context, imageRef string) (map[string]cautils.VexStatus, error)
}

type cosignVexClient struct{}

// NewVexClient creates a new VexClient.
func NewVexClient() VexClient {
	return &cosignVexClient{}
}

func (c *cosignVexClient) GetVexStatuses(ctx context.Context, imageRef string) (map[string]cautils.VexStatus, error) {
	// In a real implementation, this would use cosign.VerifyImageAttestations
	// to fetch the attestation payload, and then parse it using vex.Parse().
	// For now, we return an empty map to satisfy the interface.
	_ = cosign.CheckOpts{}
	_ = vex.VEX{}

	return make(map[string]cautils.VexStatus), nil
}
