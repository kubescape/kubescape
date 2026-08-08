package fixhandler

import (
	"encoding/json"
	"fmt"
	"strings"

	storagev1beta1 "github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

// FixSuggestion represents a suggested fix based on drift detection
type FixSuggestion struct {
	YamlExpression string
}

// DetectProfileDrift analyzes a ContainerProfile against a manifest and returns a list of fixes
func DetectProfileDrift(manifest []byte, profile *storagev1beta1.ContainerProfile, workloadKind, containerName string, documentIndexInYaml int) []FixSuggestion {
	var fixes []FixSuggestion

	var obj map[string]interface{}
	if err := json.Unmarshal(manifest, &obj); err != nil {
		return fixes
	}

	var containersPath string
	var containersList []interface{}

	specRaw, ok := obj["spec"].(map[string]interface{})
	if !ok {
		return fixes
	}

	switch strings.ToLower(workloadKind) {
	case "pod":
		containersPath = "spec.containers"
		if cnts, ok := specRaw["containers"].([]interface{}); ok {
			containersList = cnts
		}
	default:
		containersPath = "spec.template.spec.containers"
		if template, ok := specRaw["template"].(map[string]interface{}); ok {
			if tspec, ok := template["spec"].(map[string]interface{}); ok {
				if cnts, ok := tspec["containers"].([]interface{}); ok {
					containersList = cnts
				}
			}
		}
	}

	containerIndex := 0
	var containerObj map[string]interface{}
	for i, c := range containersList {
		if cmap, ok := c.(map[string]interface{}); ok {
			if name, ok := cmap["name"].(string); ok && name == containerName {
				containerIndex = i
				containerObj = cmap
				break
			}
		}
	}

	baseContextPath := fmt.Sprintf("%s[%d].securityContext", containersPath, containerIndex)

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
		expr := FixPathToValidYamlExpression(baseContextPath+".readOnlyRootFilesystem", "true", documentIndexInYaml)
		fixes = append(fixes, FixSuggestion{YamlExpression: expr})
	}

	// 2. Capabilities Check
	existingDrops := make(map[string]bool)
	if containerObj != nil {
		if sc, ok := containerObj["securityContext"].(map[string]interface{}); ok {
			if caps, ok := sc["capabilities"].(map[string]interface{}); ok {
				if dropList, ok := caps["drop"].([]interface{}); ok {
					for _, d := range dropList {
						if dStr, ok := d.(string); ok {
							existingDrops[dStr] = true
						}
					}
				}
			}
		}
	}

	if len(profile.Spec.Capabilities) == 0 {
		if !existingDrops["ALL"] {
			var finalDrops []string
			for k := range existingDrops {
				finalDrops = append(finalDrops, "\""+k+"\"")
			}
			finalDrops = append(finalDrops, "\"ALL\"")
			dropsValue := "[" + strings.Join(finalDrops, ",") + "]"
			expr := FixPathToValidYamlExpression(baseContextPath+".capabilities.drop", dropsValue, documentIndexInYaml)
			fixes = append(fixes, FixSuggestion{YamlExpression: expr})
		}
	} else {
		exercised := make(map[string]bool)
		for _, cap := range profile.Spec.Capabilities {
			exercised[cap] = true
		}

		var dropsToAdd []string
		if !exercised["SYS_ADMIN"] && !existingDrops["SYS_ADMIN"] {
			dropsToAdd = append(dropsToAdd, "\"SYS_ADMIN\"")
			existingDrops["SYS_ADMIN"] = true
		}
		if !exercised["NET_ADMIN"] && !existingDrops["NET_ADMIN"] {
			dropsToAdd = append(dropsToAdd, "\"NET_ADMIN\"")
			existingDrops["NET_ADMIN"] = true
		}

		if len(dropsToAdd) > 0 {
			var finalDrops []string
			for k := range existingDrops {
				finalDrops = append(finalDrops, "\""+k+"\"")
			}
			dropsValue := "[" + strings.Join(finalDrops, ",") + "]"
			expr := FixPathToValidYamlExpression(baseContextPath+".capabilities.drop", dropsValue, documentIndexInYaml)
			fixes = append(fixes, FixSuggestion{YamlExpression: expr})
		}
	}

	return fixes
}
