package securityexception

import (
	"github.com/armosec/armoapi-go/armotypes"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
)

const (
	securityExceptionAPIVersion = "kubescape.io/v1"
	crdKindAttribute            = "securityExceptionKind"
	crdNameAttribute            = "securityExceptionName"
	crdNamespaceAttribute       = "securityExceptionNamespace"
	crdUIDAttribute             = "securityExceptionUID"
)

// CRDReference identifies the SecurityException or ClusterSecurityException that produced a policy.
type CRDReference struct {
	Kind      string
	Name      string
	Namespace string
	UID       string
}

// CRDReferenceAttributes builds attribute entries that mark a policy as CRD-backed.
func CRDReferenceAttributes(ref CRDReference) map[string]interface{} {
	attrs := map[string]interface{}{
		crdKindAttribute: ref.Kind,
		crdNameAttribute: ref.Name,
	}
	if ref.Namespace != "" {
		attrs[crdNamespaceAttribute] = ref.Namespace
	}
	if ref.UID != "" {
		attrs[crdUIDAttribute] = ref.UID
	}
	return attrs
}

// CRDReferenceFromPolicy extracts the CRD reference from a PostureExceptionPolicy.
func CRDReferenceFromPolicy(policy armotypes.PostureExceptionPolicy) (CRDReference, bool) {
	if policy.Attributes == nil {
		return CRDReference{}, false
	}
	kind, ok := getStringAttribute(policy.Attributes, crdKindAttribute)
	if !ok {
		return CRDReference{}, false
	}
	name, ok := getStringAttribute(policy.Attributes, crdNameAttribute)
	if !ok {
		return CRDReference{}, false
	}
	namespace, _ := getStringAttribute(policy.Attributes, crdNamespaceAttribute)
	uid, _ := getStringAttribute(policy.Attributes, crdUIDAttribute)
	return CRDReference{
		Kind:      kind,
		Name:      name,
		Namespace: namespace,
		UID:       uid,
	}, true
}

// UnstructuredForCRD builds an unstructured object to use as an Event reference.
func UnstructuredForCRD(ref CRDReference) *unstructured.Unstructured {
	obj := &unstructured.Unstructured{}
	obj.SetAPIVersion(securityExceptionAPIVersion)
	obj.SetKind(ref.Kind)
	obj.SetName(ref.Name)
	if ref.Namespace != "" {
		obj.SetNamespace(ref.Namespace)
	}
	if ref.UID != "" {
		obj.SetUID(types.UID(ref.UID))
	}
	return obj
}

func getStringAttribute(attrs map[string]interface{}, key string) (string, bool) {
	raw, ok := attrs[key]
	if !ok {
		return "", false
	}
	val, ok := raw.(string)
	if !ok || val == "" {
		return "", false
	}
	return val, true
}
