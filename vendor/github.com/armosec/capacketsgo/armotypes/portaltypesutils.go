package armotypes

import "github.com/golang/glog"

var IgnoreLabels = []string{AttributeCluster, AttributeNamespace}

// DigestPortalDesignator - get cluster namespace and labels from designator
func DigestPortalDesignator(designator *PortalDesignator) (string, string, map[string]string) {
	switch designator.DesignatorType {
	case DesignatorAttributes:
		return DigestAttributesDesignator(designator.Attributes)
	// case DesignatorWlid: TODO
	// case DesignatorWildWlid: TODO
	default:
		glog.Warningf("in 'digestPortalDesignator' designator type: '%v' not yet supported. please contact Armo team", designator.DesignatorType)
	}
	return "", "", nil
}

func DigestAttributesDesignator(attributes map[string]string) (string, string, map[string]string) {
	cluster := ""
	namespace := ""
	labels := map[string]string{}
	if attributes == nil || len(attributes) == 0 {
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
