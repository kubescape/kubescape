package secrethandling

import (
	"bytes"
	"encoding/binary"
	"strings"
)

// API fields
var (
	WlidPrefix           = "wlid://"
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
)

// SecretTLVTag the tlv tag
var SecretTLVTag = []byte{231, 197, 24, 237}

func init() {
	for _, kind := range K8SKindsList {
		KindReverseMap[strings.ToLower(strings.Replace(kind, "-", "", -1))] = kind
	}
	for _, kind := range NativeKindsList {
		KindReverseMap[strings.ToLower(strings.Replace(kind, "-", "", -1))] = kind
	}
}

// IsKindK8S returns true if kind is a k8s
func IsKindK8S(k string) bool {
	if val, ok := KindReverseMap[k]; ok {
		k = val
	}
	for _, k8sKind := range K8SKindsList {
		if k == k8sKind {
			return true
		}
	}
	return false
}

// HasSecretTLV is the byte slice an encrypted secret
func HasSecretTLV(secret []byte) bool {
	return bytes.HasPrefix(secret, SecretTLVTag)
}

// GetSecretTLVLength return TLV length
func GetSecretTLVLength(secret []byte) uint32 {
	length := secret[len(SecretTLVTag) : len(SecretTLVTag)+4]
	return uint32(len(SecretTLVTag)+4) + binary.BigEndian.Uint32(length)
}
