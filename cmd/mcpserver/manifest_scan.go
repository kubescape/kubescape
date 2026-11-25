package mcpserver

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/pkg/resourcehandler"
	apisv1 "github.com/kubescape/opa-utils/httpserver/apis/v1"
)

const maxManifestBytes = 2 << 20 // 2 MiB limit for in-memory manifest strings

// runManifestScan executes an in-memory scan against a YAML or JSON manifest string.
func (ksServer *KubescapeMcpserver) runManifestScan(ctx context.Context, manifest string, frameworkName string, controlIDs []string, filters ...scanFilterArgs) ([]byte, error) {
	manifestBytes := []byte(manifest)
	if len(manifestBytes) > maxManifestBytes {
		return nil, fmt.Errorf("manifest exceeds maximum allowed size of %d bytes", maxManifestBytes)
	}
	if len(strings.TrimSpace(manifest)) == 0 {
		return nil, errors.New("manifest content cannot be empty")
	}

	var policyIdentifiers []cautils.PolicyIdentifier
	label := "Manifest"
	if len(controlIDs) > 0 {
		policyIdentifiers = make([]cautils.PolicyIdentifier, len(controlIDs))
		for i, id := range controlIDs {
			policyIdentifiers[i] = cautils.PolicyIdentifier{Kind: apisv1.KindControl, Identifier: id}
		}
		label = "Manifest Controls"
	} else {
		if frameworkName == "" {
			frameworkName = "nsa"
		}
		policyIdentifiers = []cautils.PolicyIdentifier{
			{Kind: apisv1.KindFramework, Identifier: frameworkName},
		}
	}

	manifestHandler := resourcehandler.NewManifestResourceHandler(manifestBytes)

	req := scanRequest{
		policyIdentifiers:   policyIdentifiers,
		label:               label,
		wantComplianceScore: true,
		rsrcHandler:         manifestHandler,
		inMemoryManifest:    true,
		workspaceDir:        ksServer.workspaceDir,
	}
	if len(filters) > 0 {
		filters[0].applyToRequest(&req)
	}

	return runScan(ctx, ksServer, req)
}
