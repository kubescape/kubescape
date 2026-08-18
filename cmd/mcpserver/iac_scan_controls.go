package mcpserver

import (
	"context"
	"fmt"
	"strings"

	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/pkg/resourcehandler"
	apisv1 "github.com/kubescape/opa-utils/httpserver/apis/v1"
)

func (ksServer *KubescapeMcpserver) runIaCScanControls(ctx context.Context, path string, controlIDs []string) ([]byte, error) {
	filtered := make([]string, 0, len(controlIDs))
	for _, id := range controlIDs {
		if id = strings.TrimSpace(id); id != "" {
			filtered = append(filtered, id)
		}
	}
	if len(filtered) == 0 {
		return nil, fmt.Errorf("at least one control ID is required")
	}
	if path == "" {
		return nil, fmt.Errorf("path is required")
	}
	policyIdentifiers := make([]cautils.PolicyIdentifier, len(filtered))
	for i, id := range filtered {
		policyIdentifiers[i] = cautils.PolicyIdentifier{Kind: apisv1.KindControl, Identifier: id}
	}
	fileHandler := resourcehandler.NewFileResourceHandler()
	return runScan(ctx, ksServer, "", policyIdentifiers, "Local IaC Control", false, fileHandler, []string{path}, nil)
}
