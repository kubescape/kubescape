package cautils

import (
	"fmt"
	"strings"
)

// API fields
var (
	WlidPrefix           = "wlid://"
	SidPrefix            = "sid://"
	ClusterWlidPrefix    = "cluster-"
	NamespaceWlidPrefix  = "namespace-"
	DataCenterWlidPrefix = "datacenter-"
	ProjectWlidPrefix    = "project-"
	SecretSIDPrefix      = "secret-"
	SubSecretSIDPrefix   = "subsecret-"
	K8SKindsList         = []string{"ComponentStatus", "ConfigMap", "ControllerRevision", "CronJob",
		"CustomResourceDefinition", "DaemonSet", "Deployment", "Endpoints", "Event", "HorizontalPodAutoscaler",
		"Ingress", "Job", "Lease", "LimitRange", "LocalSubjectAccessReview", "MutatingWebhookConfiguration",
		"Namespace", "NetworkPolicy", "Node", "PersistentVolume", "PersistentVolumeClaim", "Pod",
		"PodDisruptionBudget", "PodSecurityPolicy", "PodTemplate", "PriorityClass", "ReplicaSet",
		"ReplicationController", "ResourceQuota", "Role", "RoleBinding", "Secret", "SelfSubjectAccessReview",
		"SelfSubjectRulesReview", "Service", "ServiceAccount", "StatefulSet", "StorageClass",
		"SubjectAccessReview", "TokenReview", "ValidatingWebhookConfiguration", "VolumeAttachment"}
	NativeKindsList = []string{"Dockerized", "Native"}
	KindReverseMap  = map[string]string{}
	dataImagesList  = []string{}
)

func IsWlid(id string) bool {
	return strings.HasPrefix(id, WlidPrefix)
}

func IsSid(id string) bool {
	return strings.HasPrefix(id, SidPrefix)
}

// GetK8SKindFronList get the calculated wlid
func GetK8SKindFronList(kind string) string { // TODO GetK8SKindFromList
	for i := range K8SKindsList {
		if strings.ToLower(kind) == strings.ToLower(K8SKindsList[i]) {
			return K8SKindsList[i]
		}
	}
	return kind
}

// IsK8SKindInList Check if the kind is a known kind
func IsK8SKindInList(kind string) bool {
	for i := range K8SKindsList {
		if strings.ToLower(kind) == strings.ToLower(K8SKindsList[i]) {
			return true
		}
	}
	return false
}

// generateWLID
func generateWLID(pLevel0, level0, pLevel1, level1, k, name string) string {
	kind := strings.ToLower(k)
	kind = strings.Replace(kind, "-", "", -1)

	wlid := WlidPrefix
	wlid += fmt.Sprintf("%s%s", pLevel0, level0)
	if level1 == "" {
		return wlid
	}
	wlid += fmt.Sprintf("/%s%s", pLevel1, level1)

	if kind == "" {
		return wlid
	}
	wlid += fmt.Sprintf("/%s", kind)

	if name == "" {
		return wlid
	}
	wlid += fmt.Sprintf("-%s", name)

	return wlid
}

// GetWLID get the calculated wlid
func GetWLID(level0, level1, k, name string) string {
	return generateWLID(ClusterWlidPrefix, level0, NamespaceWlidPrefix, level1, k, name)
}

// GetK8sWLID get the k8s calculated wlid
func GetK8sWLID(level0, level1, k, name string) string {
	return generateWLID(ClusterWlidPrefix, level0, NamespaceWlidPrefix, level1, k, name)
}

// GetNativeWLID get the native calculated wlid
func GetNativeWLID(level0, level1, k, name string) string {
	return generateWLID(DataCenterWlidPrefix, level0, ProjectWlidPrefix, level1, k, name)
}

// WildWlidContainsWlid does WildWlid contains Wlid
func WildWlidContainsWlid(wildWlid, wlid string) bool { // TODO- test
	if wildWlid == wlid {
		return true
	}
	wildWlidR, _ := RestoreMicroserviceIDsFromSpiffe(wildWlid)
	wlidR, _ := RestoreMicroserviceIDsFromSpiffe(wlid)
	if len(wildWlidR) > len(wildWlidR) {
		// invalid wlid
		return false
	}

	for i := range wildWlidR {
		if wildWlidR[i] != wlidR[i] {
			return false
		}
	}
	return true
}

func restoreInnerIdentifiersFromID(spiffeSlices []string) []string {
	if len(spiffeSlices) >= 1 && strings.HasPrefix(spiffeSlices[0], ClusterWlidPrefix) {
		spiffeSlices[0] = spiffeSlices[0][len(ClusterWlidPrefix):]
	}
	if len(spiffeSlices) >= 2 && strings.HasPrefix(spiffeSlices[1], NamespaceWlidPrefix) {
		spiffeSlices[1] = spiffeSlices[1][len(NamespaceWlidPrefix):]
	}
	if len(spiffeSlices) >= 3 && strings.Contains(spiffeSlices[2], "-") {
		dashIdx := strings.Index(spiffeSlices[2], "-")
		spiffeSlices = append(spiffeSlices, spiffeSlices[2][dashIdx+1:])
		spiffeSlices[2] = spiffeSlices[2][:dashIdx]
		if val, ok := KindReverseMap[spiffeSlices[2]]; ok {
			spiffeSlices[2] = val
		}
	}
	return spiffeSlices
}

// RestoreMicroserviceIDsFromSpiffe -
func RestoreMicroserviceIDsFromSpiffe(spiffe string) ([]string, error) {
	if spiffe == "" {
		return nil, fmt.Errorf("in RestoreMicroserviceIDsFromSpiffe, expecting valid wlid recieved empty string")
	}

	if StringHasWhitespace(spiffe) {
		return nil, fmt.Errorf("wlid %s invalid. whitespace found", spiffe)
	}

	if strings.HasPrefix(spiffe, WlidPrefix) {
		spiffe = spiffe[len(WlidPrefix):]
	} else if strings.HasPrefix(spiffe, SidPrefix) {
		spiffe = spiffe[len(SidPrefix):]
	}
	spiffeSlices := strings.Split(spiffe, "/")
	// The documented WLID format (https://cyberarmorio.sharepoint.com/sites/development2/Shared%20Documents/kubernetes_design1.docx?web=1)
	if len(spiffeSlices) <= 3 {
		spiffeSlices = restoreInnerIdentifiersFromID(spiffeSlices)
	}
	if len(spiffeSlices) != 4 { // first used WLID, deprecated since 24.10.2019
		return spiffeSlices, fmt.Errorf("invalid WLID format. format received: %v", spiffeSlices)
	}

	for i := range spiffeSlices {
		if spiffeSlices[i] == "" {
			return spiffeSlices, fmt.Errorf("one or more entities are empty, spiffeSlices: %v", spiffeSlices)
		}
	}

	return spiffeSlices, nil
}

// RestoreMicroserviceIDsFromSpiffe -
func RestoreMicroserviceIDs(spiffe string) []string {
	if spiffe == "" {
		return []string{}
	}

	if StringHasWhitespace(spiffe) {
		return []string{}
	}

	if strings.HasPrefix(spiffe, WlidPrefix) {
		spiffe = spiffe[len(WlidPrefix):]
	} else if strings.HasPrefix(spiffe, SidPrefix) {
		spiffe = spiffe[len(SidPrefix):]
	}
	spiffeSlices := strings.Split(spiffe, "/")

	return restoreInnerIdentifiersFromID(spiffeSlices)
}

// GetClusterFromWlid parse wlid and get cluster
func GetClusterFromWlid(wlid string) string {
	r := RestoreMicroserviceIDs(wlid)
	if len(r) >= 1 {
		return r[0]
	}
	return ""
}

// GetNamespaceFromWlid parse wlid and get Namespace
func GetNamespaceFromWlid(wlid string) string {
	r := RestoreMicroserviceIDs(wlid)
	if len(r) >= 2 {
		return r[1]
	}
	return ""
}

// GetKindFromWlid parse wlid and get kind
func GetKindFromWlid(wlid string) string {
	r := RestoreMicroserviceIDs(wlid)
	if len(r) >= 3 {
		return GetK8SKindFronList(r[2])
	}
	return ""
}

// GetNameFromWlid parse wlid and get name
func GetNameFromWlid(wlid string) string {
	r := RestoreMicroserviceIDs(wlid)
	if len(r) >= 4 {
		return GetK8SKindFronList(r[3])
	}
	return ""
}

// IsWlidValid test if wlid is a valid wlid
func IsWlidValid(wlid string) error {
	_, err := RestoreMicroserviceIDsFromSpiffe(wlid)
	return err
}

// StringHasWhitespace check if a string has whitespace
func StringHasWhitespace(str string) bool {
	if whitespace := strings.Index(str, " "); whitespace != -1 {
		return true
	}
	return false
}
