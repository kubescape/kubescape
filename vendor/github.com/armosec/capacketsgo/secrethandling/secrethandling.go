package secrethandling

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
)

// Global variables to use in another packages
var (
	ArmoShadowSecretInitalLabel = "cyberarmor.initial"
	ArmoShadowSecretFlagLabel   = "cyberarmor.secret"
	ArmoShadowSecretPrefix      = "ca-"
	ArmoShadowSubsecretSuffix   = ".castatus"
)

// CAK8SMeta holds common metadata about k8s objects
type CAK8SMeta struct {
	CustomerGUID   string    `json:"customerGUID"`
	CAClusterName  string    `json:"caClusterName,omitempty"`
	LastUpdateTime time.Time `json:"caLastUpdate"`
	IsActive       bool      `json:"isActive"`
}

// K8SSecret represents single k8s secret in cluster
type K8SSecret struct {
	CAK8SMeta     `json:",inline"`
	corev1.Secret `json:",inline"`
	Protected     int `json:"protected"`
}

// DEPRECATED - "github.com/armosec/capacketsgo/armotypes"
// PortalBase holds basic items data from portal BE
type PortalBase struct {
	GUID       string                 `json:"guid"`
	Name       string                 `json:"name"`
	Attributes map[string]interface{} `json:"attributes,omitempty"` // could be string
}

// DEPRECATED - "github.com/armosec/capacketsgo/armotypes"
// PortalDesignator represented single designation options
type PortalDesignator struct {
	DesignatorType string            `json:"designatorType"`
	WLID           string            `json:"wlid"`
	WildWLID       string            `json:"wildwlid"`
	Attributes     map[string]string `json:"attributes"`
}

// SecretAccessPolicy represent list od workloads allows to access some secrets
// Notice that in K8S, workload can use secret only in case they are in the same namespace
type SecretAccessPolicy struct {
	PortalBase   `json:",inline"`
	PolicyType   string                   `json:"policyType"`
	CreationDate string                   `json:"creation_time"`
	Designators  []PortalDesignator       `json:"designators"`
	Secrets      []PortalSecretDefinition `json:"secrets"`
}

// PortalSecretDefinition defines a relation between keys and sub secrets of specific secret
type PortalSecretDefinition struct {
	SecretID string                      `json:"sid"`
	KeyIDs   []PortalSubSecretDefinition `json:"keyIDs"`
}

// PortalSubSecretDefinition defines a relation between keyID and sub secret
type PortalSubSecretDefinition struct {
	SubSecretName string `json:"subSecretName"`
	KeyID         string `json:"keyID"`
}

var supportedSecretsTypes = []corev1.SecretType{corev1.SecretTypeOpaque}

// LoadSubSecretsIntoPolicy fills the subsecrets names + keyIDs in this policy
// returns if this policy had changed during the process
func (sap *SecretAccessPolicy) LoadSubSecretsIntoPolicy(shadowSecret *K8SSecret, initialSID string) bool {
	isChanged := false
	if !shadowSecret.IsActive {
		return false
	}
	for secIdx := range sap.Secrets {
		if sap.Secrets[secIdx].SecretID == initialSID {
			if sap.Secrets[secIdx].KeyIDs == nil {
				sap.Secrets[secIdx].KeyIDs = make([]PortalSubSecretDefinition, 0)
			}
			policySubSecs := make(map[string]map[string]bool, len(sap.Secrets[secIdx].KeyIDs))
			// collecting sub-secrets and keyIDs currently exists in the policy
			for subSecIdx := range sap.Secrets[secIdx].KeyIDs {
				if _, ok := policySubSecs[sap.Secrets[secIdx].KeyIDs[subSecIdx].SubSecretName]; !ok {
					policySubSecs[sap.Secrets[secIdx].KeyIDs[subSecIdx].SubSecretName] = make(map[string]bool)
				}
				policySubSecs[sap.Secrets[secIdx].KeyIDs[subSecIdx].SubSecretName][sap.Secrets[secIdx].KeyIDs[subSecIdx].KeyID] = true
			}

			if shadowSecret.Annotations != nil {
				// filling new sub-secrets or new keyIDs in the policy
				for anno := range shadowSecret.Annotations {
					subSecName := GetSubSecretFromAnnotation(anno)
					subSecKeyID := GetSubSecretKeyIDFromAnnotation(shadowSecret.Annotations[anno])
					if subSecName != "" && subSecKeyID != "" {
						subSecKeyIDFound := false
						for subSecIdx := range sap.Secrets[secIdx].KeyIDs {
							subSecKeyIDFound = updateSubsecretPolicy(&sap.Secrets[secIdx].KeyIDs[subSecIdx], subSecName, subSecKeyID)
						}
						if subSecKeyIDFound {
							isChanged = subSecKeyIDFound
							continue
						}
						if _, ok := policySubSecs[subSecName]; ok {
							if _, ok := policySubSecs[subSecName][subSecKeyID]; ok {
								continue
							}
						}
						isChanged = true
						sap.Secrets[secIdx].KeyIDs = append(sap.Secrets[secIdx].KeyIDs, PortalSubSecretDefinition{
							SubSecretName: subSecName,
							KeyID:         subSecKeyID,
						})
					}
				}
			}
		}
	}
	return isChanged
}

func updateSubsecretPolicy(portalSubSecretDefinition *PortalSubSecretDefinition, subSecName, subSecKeyID string) bool {
	if portalSubSecretDefinition.SubSecretName == "" && portalSubSecretDefinition.KeyID == "" { // empty secret name and empty secret id
		portalSubSecretDefinition.SubSecretName = subSecName
		portalSubSecretDefinition.KeyID = subSecKeyID
		return true
	}
	if portalSubSecretDefinition.SubSecretName == subSecName {
		if portalSubSecretDefinition.KeyID == "" || portalSubSecretDefinition.KeyID != subSecKeyID { // empty/old secretID
			portalSubSecretDefinition.KeyID = subSecKeyID
			return true
		}
	}
	if portalSubSecretDefinition.SubSecretName == "" { // empty secret name
		if portalSubSecretDefinition.KeyID == subSecKeyID {
			portalSubSecretDefinition.SubSecretName = subSecName
			return true
		}
	}
	return false
}

// GetSubSecretKeyIDFromAnnotation extract from annotation value the desired key id
func GetSubSecretKeyIDFromAnnotation(annotationVal string) string {
	// described in https://cyberarmorio.sharepoint.com/sites/development2/Shared%20Documents/Kubernetes%20secrets.docx?web=1, data definitions section
	castatusBytes, err := base64.StdEncoding.DecodeString(annotationVal)
	if err != nil {
		zap.L().Error("In GetSubSecretKeyIDFromAnnotation failed to DecodeString", zap.Error(err))
		return ""
	}
	return hex.EncodeToString(castatusBytes[24 : 24+16])
}

// GetSubSecretFromAnnotation extract from annotation tag the desired sub-secret name
func GetSubSecretFromAnnotation(annotationTag string) string {
	annotSlices := strings.SplitN(annotationTag, "/", 2)
	if len(annotSlices) == 2 && annotSlices[0] == "cyberarmor" {
		if len(annotSlices) == 2 && annotSlices[0] == "cyberarmor" {
			sepIdx := strings.LastIndex(annotSlices[1], ".")
			if len(annotSlices[1]) > -1 && annotSlices[1][sepIdx+1:] == "castatus" {
				return annotSlices[1][:sepIdx]
			}
		}
	}
	return ""
}

// GetID returnd the sid of the secret
func (sec *K8SSecret) GetID() string {
	return fmt.Sprintf("sid://cluster-%s/namespace-%s/secret-%s", sec.CAClusterName, sec.Namespace, sec.Name)
}

// SplitSecretID splits the secret id string into cluster, namespace, secret-name [,sub-secret-name]
func SplitSecretID(sid string) ([]string, error) {
	if err := ValidateSecretID(sid); err != nil {
		return nil, err
	}

	splits := strings.Split(sid, "/")
	splitsLen := len(splits)
	if splitsLen < 5 || splitsLen > 6 {
		return nil, fmt.Errorf("invalid sid: '%s', to short", sid)
	}
	kind := ""
	if strings.HasPrefix(splits[2], ClusterWlidPrefix) && strings.HasPrefix(splits[3], NamespaceWlidPrefix) {
		kind = "k8s"
	} else if strings.HasPrefix(splits[2], DataCenterWlidPrefix) && strings.HasPrefix(splits[3], ProjectWlidPrefix) {
		kind = "native"
	} else {
		return nil, fmt.Errorf("invalid sid: '%s', unknown kind", sid)
	}

	rslt := make([]string, 0, 4)
	if kind == "k8s" {
		rslt = append(rslt, splits[2][len(ClusterWlidPrefix):])
		rslt = append(rslt, splits[3][len(NamespaceWlidPrefix):])
	} else {
		rslt = append(rslt, splits[2][len(DataCenterWlidPrefix):])
		rslt = append(rslt, splits[3][len(ProjectWlidPrefix):])
	}
	rslt = append(rslt, splits[4][len(SecretSIDPrefix):])
	if len(splits) > 5 {
		rslt = append(rslt, splits[5][len(SubSecretSIDPrefix):])
	}
	return rslt, nil
}

// ValidateSecretID test secret validation
func ValidateSecretID(sid string) error {
	if sid == "" {
		return fmt.Errorf("secret-id not found")
	}
	splits := strings.Split(sid, "/")
	splitsLen := len(splits)
	if splitsLen < 3 || splitsLen > 6 {
		return fmt.Errorf("invalid sid: %s, to short or to long", sid)
	}
	level1 := ""
	if splits[2] != "" {
		if strings.HasPrefix(splits[2], ClusterWlidPrefix) {
			if splits[2][len(ClusterWlidPrefix):] != "" {
				level1 = NamespaceWlidPrefix
			}
		} else {
			if strings.HasPrefix(splits[2], DataCenterWlidPrefix) {
				if splits[2][len(DataCenterWlidPrefix):] != "" {
					level1 = ProjectWlidPrefix
				}
			}
		}
	}
	if level1 == "" {
		return fmt.Errorf("invalid sid: %s, missing cluster/datacenter", sid)
	}

	if splitsLen >= 4 {
		if splits[3] != "" && (!strings.HasPrefix(splits[3], level1) || splits[3][len(level1):] == "") {
			return fmt.Errorf("invalid sid: %s, empty namespace/project", sid)
		}
	}
	if splitsLen >= 5 {
		if splits[4] != "" && (!strings.HasPrefix(splits[4], SecretSIDPrefix) || splits[4][len(SecretSIDPrefix):] == "") {
			return fmt.Errorf("invalid sid: %s, empty secret name", sid)
		}
	}
	if splitsLen == 6 {
		if splits[5] != "" && (!strings.HasPrefix(splits[5], SubSecretSIDPrefix) || splits[5][len(SubSecretSIDPrefix):] == "") {
			return fmt.Errorf("invalid sid: %s, empty subsecret name", sid)
		}
	}
	return nil
}

// GetSID get secret is
func GetSID(cluster, namespace, name, subsecret string) string {
	sid := fmt.Sprintf("sid://%s%s/%s%s/secret-%s", ClusterWlidPrefix, cluster, NamespaceWlidPrefix, namespace, name)
	if subsecret != "" {
		sid = fmt.Sprintf("%s/subsecret-%s", sid, subsecret)
	}
	return sid
}

// GetNativeSID get native secret is
func GetNativeSID(datacenter, project, name, subsecret string) string {
	sid := fmt.Sprintf("sid://%s%s/%s%s/secret-%s", DataCenterWlidPrefix, datacenter, ProjectWlidPrefix, project, name)
	if subsecret != "" {
		sid = fmt.Sprintf("%s/subsecret-%s", sid, subsecret)
	}
	return sid
}

// IsSIDK8s get secret kind
func IsSIDK8s(sid string) bool {
	splits := strings.Split(sid, "/")
	if sid == "sid://" || strings.HasPrefix(splits[2], ClusterWlidPrefix) {
		return true
	}
	return false
}

// GetSIDCluster get cluster name from secret-id
func GetSIDCluster(sid string) string {
	splitted, _ := SplitSecretID(sid)
	return splitted[0]
}

// GetSIDNamespace get namespace name from secret-id
func GetSIDNamespace(sid string) string {
	splitted, _ := SplitSecretID(sid)
	return splitted[1]
}

// GetSIDLevel0 get level0 name from secret-id
func GetSIDLevel0(sid string) string {
	splitted, _ := SplitSecretID(sid)
	return splitted[0]
}

// GetSIDLevel1 get level1 name from secret-id
func GetSIDLevel1(sid string) string {
	splitted, _ := SplitSecretID(sid)
	return splitted[1]
}

// GetSIDName get secret name from secret-id
func GetSIDName(sid string) string {
	splitted, _ := SplitSecretID(sid)
	return splitted[2]
}

// GetSIDSubsecret get subsecret name from secret-id, if not found, return empty string
func GetSIDSubsecret(sid string) string {
	splitted, _ := SplitSecretID(sid)
	if len(splitted) > 3 {
		return splitted[3]
	}
	return ""
}

// RemoveSIDSubsecret get subsecret name from secret-id, if not found, return empty string
func RemoveSIDSubsecret(sid string) string {
	splitted, _ := SplitSecretID(sid)
	if len(splitted) < 3 {
		return ""
	}
	if IsSIDK8s(sid) {
		return GetSID(splitted[0], splitted[1], splitted[2], "")
	}
	return GetNativeSID(splitted[0], splitted[1], splitted[2], "")
}

// GetSecretIDsFromPolicyList list secret-ids from a list of policies
func GetSecretIDsFromPolicyList(listSecretAccessPolicy []SecretAccessPolicy) map[string]SecretAccessPolicy {
	secretIDs := make(map[string]SecretAccessPolicy)
	for i := range listSecretAccessPolicy {
		secretIDsTmp := GetSecretIDsFromPolicy(&listSecretAccessPolicy[i])
		for j := range secretIDsTmp {
			secretIDs[secretIDsTmp[j]] = listSecretAccessPolicy[i]
		}
	}
	return secretIDs
}

// GetSecretIDsFromPolicy list secret-ids from a secret policy
func GetSecretIDsFromPolicy(secretAccessPolicy *SecretAccessPolicy) []string {
	secretIDs := []string{}
	if secretAccessPolicy.Secrets == nil {
		return secretIDs
	}
	for sec := range secretAccessPolicy.Secrets {
		if secretAccessPolicy.Secrets[sec].SecretID != "" {
			secretIDs = append(secretIDs, secretAccessPolicy.Secrets[sec].SecretID)
		}
	}
	return secretIDs
}

// IsSecretTypeSupported does Armo support protection on this type of secret
func IsSecretTypeSupported(secretType corev1.SecretType) bool {
	for i := range supportedSecretsTypes {
		if supportedSecretsTypes[i] == secretType {
			return true
		}
	}
	return false
}

// GenerateDefaultNamespacePolicy generate default secret access policy based on namespace
func GenerateDefaultNamespacePolicy(sid string) *SecretAccessPolicy {

	keyLevel0 := ""
	keyLevel1 := ""

	if IsSIDK8s(sid) {
		keyLevel0 = strings.TrimSuffix(ClusterWlidPrefix, "-")
		keyLevel1 = strings.TrimSuffix(NamespaceWlidPrefix, "-")
	} else {
		keyLevel0 = strings.TrimSuffix(DataCenterWlidPrefix, "-")
		keyLevel1 = strings.TrimSuffix(ProjectWlidPrefix, "-")
	}
	return &SecretAccessPolicy{
		PortalBase: PortalBase{
			Name: sid,
			Attributes: map[string]interface{}{
				"name":   "generatedInBackend",
				"policy": "generatedInBackend",
			},
		},
		CreationDate: time.Now().UTC().Format(time.RFC3339),
		PolicyType:   "secretAccessList",
		Designators: []PortalDesignator{
			{
				DesignatorType: "attributes",
				Attributes: map[string]string{
					keyLevel0: GetSIDLevel0(sid),
					keyLevel1: GetSIDLevel1(sid),
				},
			},
		},
		Secrets: []PortalSecretDefinition{
			{
				SecretID: sid,
				KeyIDs:   []PortalSubSecretDefinition{},
			},
		},
	}
}

// EditEncryptionSecretPolicy remove subsecret name from sid
func EditEncryptionSecretPolicy(secretAccessPolicy *SecretAccessPolicy) {
	if secretAccessPolicy == nil || secretAccessPolicy.Secrets == nil {
		return
	}
	for i := range secretAccessPolicy.Secrets {
		sid := secretAccessPolicy.Secrets[i].SecretID
		if secretAccessPolicy.Secrets[i].KeyIDs == nil {
			secretAccessPolicy.Secrets[i].KeyIDs = []PortalSubSecretDefinition{}
		}
		subsecret := GetSIDSubsecret(sid)
		if subsecret == "" {
			continue
		}
		secretAccessPolicy.Secrets[i].SecretID = RemoveSIDSubsecret(sid)
		found := false
		for j := range secretAccessPolicy.Secrets[i].KeyIDs {
			if secretAccessPolicy.Secrets[i].KeyIDs[j].SubSecretName == subsecret {
				found = true
			}
		}
		if len(secretAccessPolicy.Secrets[i].KeyIDs) == 0 || !found {
			secretAccessPolicy.Secrets[i].KeyIDs = append(secretAccessPolicy.Secrets[i].KeyIDs, PortalSubSecretDefinition{SubSecretName: subsecret})
		}
	}

}

// ValidateSecretAccessPolicy validate secret policy object
func ValidateSecretAccessPolicy(policy *SecretAccessPolicy) error {
	if policy == nil {
		return fmt.Errorf("empty secretAccessPolicy")
	}
	if policy.Attributes == nil {
		policy.Attributes = make(map[string]interface{})
	}
	policy.Attributes["lastEdited"] = time.Now().UTC().Format(time.RFC3339)

	if policy.PolicyType == "" {
		policy.PolicyType = "secretAccessList"
	}
	if policy.Secrets == nil || len(policy.Secrets) == 0 {
		return fmt.Errorf("no secrets found in secretAccessPolicy")
	}
	for i := range policy.Secrets {
		if policy.Secrets[i].SecretID == "" {
			return fmt.Errorf("empty SecretID found in secretAccessPolicy index %d", i)
		}
		if policy.Secrets[i].KeyIDs == nil {
			policy.Secrets[i].KeyIDs = []PortalSubSecretDefinition{}
		}
	}
	if policy.Name == "" {
		policy.Name = policy.Secrets[0].SecretID
		policy.Attributes["name"] = "nameGeneratedInBackend"
	}

	if policy.Designators != nil {
		for i := range policy.Designators {
			if policy.Designators[i].DesignatorType == "" {
				if policy.Designators[i].WLID != "" {
					policy.Designators[i].DesignatorType = "wlid"
				}
				if policy.Designators[i].WildWLID != "" {
					policy.Designators[i].DesignatorType = "wildwlid"
				}
				if policy.Designators[i].Attributes != nil && len(policy.Designators[i].Attributes) > 0 {
					policy.Designators[i].DesignatorType = "attributes"
				}
			}
		}
	}
	if policy.CreationDate == "" {
		policy.CreationDate = time.Now().UTC().Format(time.RFC3339)
	}

	return nil
}
