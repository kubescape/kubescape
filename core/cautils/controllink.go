package cautils

import (
	"fmt"
	"strings"
)

func GetControlLink(controlID string) string {
	// For CIS Controls, cis-1.1.3 will be transformed to cis-1-1-3 in documentation link.
	docLinkID := strings.ReplaceAll(controlID, ".", "-")
	return fmt.Sprintf("https://hub.armosec.io/docs/%s", strings.ToLower(docLinkID))
}
