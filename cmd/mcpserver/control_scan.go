package mcpserver

import (
	"context"
	"fmt"
	"strings"
)

func (ksServer *KubescapeMcpserver) ScanControls(ctx context.Context, namespace string, controlIDs []string) ([]byte, error) {
	filtered := make([]string, 0, len(controlIDs))
	for _, id := range controlIDs {
		if id = strings.TrimSpace(id); id != "" {
			filtered = append(filtered, id)
		}
	}
	if len(filtered) == 0 {
		return nil, fmt.Errorf("at least one control ID is required")
	}
	return runControlScan(ctx, ksServer, namespace, filtered, "Control")
}
