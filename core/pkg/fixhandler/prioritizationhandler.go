package fixhandler

import (
	"strings"

	storagev1beta1 "github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

// FixSuggestion represents a suggested fix based on drift detection
type FixSuggestion struct {
	YamlExpression string
}

// DetectProfileDrift analyzes a ContainerProfile against a manifest and returns a list of fixes
func DetectProfileDrift(manifest []byte, profile *storagev1beta1.ContainerProfile) []FixSuggestion {
	var fixes []FixSuggestion

	// We assume a single document or target the first container for simplicity in MVP
	documentIndexInYaml := 0

	// 1. Rootfs Check
	hasWrite := false
	for _, openCall := range profile.Spec.Opens {
		for _, flag := range openCall.Flags {
			if strings.Contains(flag, "O_WRONLY") || strings.Contains(flag, "O_RDWR") ||
				strings.Contains(flag, "O_CREAT") || strings.Contains(flag, "O_APPEND") {
				hasWrite = true
				break
			}
		}
		if hasWrite {
			break
		}
	}

	if !hasWrite {
		expr := FixPathToValidYamlExpression("spec.containers[0].securityContext.readOnlyRootFilesystem", "true", documentIndexInYaml)
		fixes = append(fixes, FixSuggestion{YamlExpression: expr})
	}

	// 2. Capabilities Check
	if len(profile.Spec.Capabilities) == 0 {
		expr := FixPathToValidYamlExpression("spec.containers[0].securityContext.capabilities.drop", "[\"ALL\"]", documentIndexInYaml)
		fixes = append(fixes, FixSuggestion{YamlExpression: expr})
	} else {
		exercised := make(map[string]bool)
		for _, cap := range profile.Spec.Capabilities {
			exercised[cap] = true
		}
		
		if !exercised["SYS_ADMIN"] {
			expr := FixPathToValidYamlExpression("spec.containers[0].securityContext.capabilities.drop", "[\"SYS_ADMIN\"]", documentIndexInYaml)
			fixes = append(fixes, FixSuggestion{YamlExpression: expr})
		}
		if !exercised["NET_ADMIN"] {
			expr := FixPathToValidYamlExpression("spec.containers[0].securityContext.capabilities.drop", "[\"NET_ADMIN\"]", documentIndexInYaml)
			fixes = append(fixes, FixSuggestion{YamlExpression: expr})
		}
	}

	return fixes
}
