package fixhandler

import (
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	idhelpers "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	storagev1beta1 "github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

func isValidCapability(s string) bool {
	for _, r := range s {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '_' {
			return false
		}
	}
	return len(s) > 0
}

// fsMutatingSyscalls are syscalls that change the filesystem without an open(2)
// the profile's Opens list could describe. Only their presence is evidence;
// their absence from a profile proves nothing, as event capture is not
// guaranteed to be complete.
var fsMutatingSyscalls = map[string]bool{
	"creat": true, "truncate": true, "ftruncate": true,
	"unlink": true, "unlinkat": true, "rmdir": true,
	"rename": true, "renameat": true, "renameat2": true,
	"mkdir": true, "mkdirat": true, "mknod": true, "mknodat": true,
	"link": true, "linkat": true, "symlink": true, "symlinkat": true,
	"chmod": true, "fchmod": true, "fchmodat": true,
	"chown": true, "fchown": true, "lchown": true, "fchownat": true,
	"setxattr": true, "lsetxattr": true, "fsetxattr": true,
	"removexattr": true, "lremovexattr": true, "fremovexattr": true,
	"fallocate": true, "copy_file_range": true,
	"utime": true, "utimes": true, "futimesat": true, "utimensat": true,
	"mount": true,
}

// profileMarkedIncomplete reports whether the profile's annotations explicitly
// say it is still learning or was only partially observed. Missing annotations
// are not treated as incomplete, which keeps unannotated profiles (for example
// hand-written ones) on the pre-existing behavior. A completed/full profile is
// not proof of complete coverage; it only means no such marker is present.
func profileMarkedIncomplete(profile *storagev1beta1.ContainerProfile) bool {
	annotations := profile.GetAnnotations()
	if status, ok := annotations[idhelpers.StatusMetadataKey]; ok && status != idhelpers.Completed {
		return true
	}
	if completion, ok := annotations[idhelpers.CompletionMetadataKey]; ok && completion != idhelpers.Full {
		return true
	}
	return false
}

func hasFsMutatingSyscall(profile *storagev1beta1.ContainerProfile) bool {
	for _, sc := range profile.Spec.Syscalls {
		if fsMutatingSyscalls[strings.ToLower(sc)] {
			return true
		}
	}
	return false
}

// FixSuggestion represents a suggested fix based on drift detection
type FixSuggestion struct {
	YamlExpression string
}

// DetectProfileDrift analyzes a ContainerProfile against a manifest and returns a list of fixes
func DetectProfileDrift(manifest []byte, profile *storagev1beta1.ContainerProfile, workloadKind, containerName string, documentIndexInYaml int) []FixSuggestion {
	var fixes []FixSuggestion

	if profile == nil {
		return fixes
	}

	var obj map[string]interface{}
	if err := yaml.Unmarshal(manifest, &obj); err != nil {
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
	case "cronjob":
		containersPath = "spec.jobTemplate.spec.template.spec.containers"
		if jobTemplate, ok := specRaw["jobTemplate"].(map[string]interface{}); ok {
			if jtspec, ok := jobTemplate["spec"].(map[string]interface{}); ok {
				if template, ok := jtspec["template"].(map[string]interface{}); ok {
					if tspec, ok := template["spec"].(map[string]interface{}); ok {
						if cnts, ok := tspec["containers"].([]interface{}); ok {
							containersList = cnts
						}
					}
				}
			}
		}
	case "deployment", "daemonset", "statefulset", "replicaset", "job":
		containersPath = "spec.template.spec.containers"
		if template, ok := specRaw["template"].(map[string]interface{}); ok {
			if tspec, ok := template["spec"].(map[string]interface{}); ok {
				if cnts, ok := tspec["containers"].([]interface{}); ok {
					containersList = cnts
				}
			}
		}
	default:
		return fixes
	}

	if len(containersList) == 0 {
		return fixes
	}

	containerIndex := -1
	var containerObj map[string]interface{}

	if containerName != "" {
		for i, c := range containersList {
			if cmap, ok := c.(map[string]interface{}); ok {
				if name, ok := cmap["name"].(string); ok && name == containerName {
					containerIndex = i
					containerObj = cmap
					break
				}
			}
		}
		if containerIndex == -1 {
			return fixes // containerName was specified but not found
		}
	} else {
		// if containerName is empty and multiple containers exist, return no fixes to avoid silently patching wrong container
		if len(containersList) > 1 {
			return fixes
		}
		containerIndex = 0
		if cmap, ok := containersList[0].(map[string]interface{}); ok {
			containerObj = cmap
		}
	}

	if containerObj == nil {
		return fixes
	}

	// Both the read-only rootfs and the drop-ALL suggestions are inferred from
	// something not having been observed, so they are withheld when the profile
	// says its observations are not complete.
	absenceEvidenceUsable := !profileMarkedIncomplete(profile)
	if !absenceEvidenceUsable {
		logger.L().Debug("skipping absence-based profile drift suggestions: container profile is marked incomplete",
			helpers.String("profile", profile.GetName()))
	}

	baseContextPath := fmt.Sprintf("%s[%d].securityContext", containersPath, containerIndex)

	// Check if readOnlyRootFilesystem is already set to true in the manifest
	isReadOnlyManifest := false
	if sc, ok := containerObj["securityContext"].(map[string]interface{}); ok {
		if ro, ok := sc["readOnlyRootFilesystem"].(bool); ok {
			isReadOnlyManifest = ro
		}
	}

	// 1. Rootfs Check
	if !isReadOnlyManifest && absenceEvidenceUsable {
		hasWrite := hasFsMutatingSyscall(profile)
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
	}

	// 2. Capabilities Check
	existingDrops := make(map[string]bool)
	if sc, ok := containerObj["securityContext"].(map[string]interface{}); ok {
		if caps, ok := sc["capabilities"].(map[string]interface{}); ok {
			if dropList, ok := caps["drop"].([]interface{}); ok {
				for _, d := range dropList {
					if dStr, ok := d.(string); ok {
						if isValidCapability(dStr) {
							existingDrops[dStr] = true
						}
					}
				}
			}
		}
	}

	if len(profile.Spec.Capabilities) == 0 {
		if absenceEvidenceUsable && !existingDrops["ALL"] {
			var finalDrops []string
			for k := range existingDrops {
				finalDrops = append(finalDrops, "\""+k+"\"")
			}
			sort.Strings(finalDrops)
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
			sort.Strings(finalDrops)
			dropsValue := "[" + strings.Join(finalDrops, ",") + "]"
			expr := FixPathToValidYamlExpression(baseContextPath+".capabilities.drop", dropsValue, documentIndexInYaml)
			fixes = append(fixes, FixSuggestion{YamlExpression: expr})
		}
	}

	return fixes
}
