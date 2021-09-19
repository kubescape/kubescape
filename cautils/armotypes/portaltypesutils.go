package armotypes

import (
	"github.com/armosec/kubescape/cautils/cautils"
	"github.com/golang/glog"
)

var IgnoreLabels = []string{AttributeCluster, AttributeNamespace}

func (designator *PortalDesignator) GetCluster() string {
	cluster, _, _, _, _ := designator.DigestPortalDesignator()
	return cluster
}

func (designator *PortalDesignator) GetNamespace() string {
	_, namespace, _, _, _ := designator.DigestPortalDesignator()
	return namespace
}

func (designator *PortalDesignator) GetKind() string {
	_, _, kind, _, _ := designator.DigestPortalDesignator()
	return kind
}

func (designator *PortalDesignator) GetName() string {
	_, _, _, name, _ := designator.DigestPortalDesignator()
	return name
}
func (designator *PortalDesignator) GetLabels() map[string]string {
	_, _, _, _, labels := designator.DigestPortalDesignator()
	return labels
}

// DigestPortalDesignator - get cluster namespace and labels from designator
func (designator *PortalDesignator) DigestPortalDesignator() (string, string, string, string, map[string]string) {
	switch designator.DesignatorType.ToLower() {
	case DesignatorAttributes.ToLower(), DesignatorAttribute.ToLower():
		return designator.DigestAttributesDesignator()
	case DesignatorWlid.ToLower(), DesignatorWildWlid.ToLower():
		return cautils.GetClusterFromWlid(designator.WLID), cautils.GetNamespaceFromWlid(designator.WLID), cautils.GetKindFromWlid(designator.WLID), cautils.GetNameFromWlid(designator.WLID), map[string]string{}
	// case DesignatorSid: // TODO
	default:
		glog.Warningf("in 'digestPortalDesignator' designator type: '%v' not yet supported. please contact Armo team", designator.DesignatorType)
	}
	return "", "", "", "", nil
}

func (designator *PortalDesignator) DigestAttributesDesignator() (string, string, string, string, map[string]string) {
	cluster := ""
	namespace := ""
	kind := ""
	name := ""
	labels := map[string]string{}
	attributes := designator.Attributes
	if attributes == nil {
		return cluster, namespace, kind, name, labels
	}
	for k, v := range attributes {
		labels[k] = v
	}
	if v, ok := attributes[AttributeNamespace]; ok {
		namespace = v
		delete(labels, AttributeNamespace)
	}
	if v, ok := attributes[AttributeCluster]; ok {
		cluster = v
		delete(labels, AttributeCluster)
	}
	if v, ok := attributes[AttributeKind]; ok {
		kind = v
		delete(labels, AttributeKind)
	}
	if v, ok := attributes[AttributeName]; ok {
		name = v
		delete(labels, AttributeName)
	}
	return cluster, namespace, kind, name, labels
}

// DigestPortalDesignator DEPRECATED. use designator.DigestPortalDesignator() - get cluster namespace and labels from designator
func DigestPortalDesignator(designator *PortalDesignator) (string, string, map[string]string) {
	switch designator.DesignatorType {
	case DesignatorAttributes, DesignatorAttribute:
		return DigestAttributesDesignator(designator.Attributes)
	case DesignatorWlid, DesignatorWildWlid:
		return cautils.GetClusterFromWlid(designator.WLID), cautils.GetNamespaceFromWlid(designator.WLID), map[string]string{}
	// case DesignatorSid: // TODO
	default:
		glog.Warningf("in 'digestPortalDesignator' designator type: '%v' not yet supported. please contact Armo team", designator.DesignatorType)
	}
	return "", "", nil
}
func DigestAttributesDesignator(attributes map[string]string) (string, string, map[string]string) {
	cluster := ""
	namespace := ""
	labels := map[string]string{}
	if attributes == nil {
		return cluster, namespace, labels
	}
	for k, v := range attributes {
		labels[k] = v
	}
	if v, ok := attributes[AttributeNamespace]; ok {
		namespace = v
		delete(labels, AttributeNamespace)
	}
	if v, ok := attributes[AttributeCluster]; ok {
		cluster = v
		delete(labels, AttributeCluster)
	}

	return cluster, namespace, labels
}
