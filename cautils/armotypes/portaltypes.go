package armotypes

const (
	CostumerGuidQuery   = "costumerGUID"
	ClusterNameQuery    = "cluster"
	DatacenterNameQuery = "datacenter"
	NamespaceQuery      = "namespace"
	ProjectQuery        = "project"
	WlidQuery           = "wlid"
	SidQuery            = "sid"
)

// PortalBase holds basic items data from portal BE
type PortalBase struct {
	GUID       string                 `json:"guid"`
	Name       string                 `json:"name"`
	Attributes map[string]interface{} `json:"attributes,omitempty"` // could be string
}

type DesignatorType string

// Supported designators
const (
	DesignatorAttributes DesignatorType = "Attributes"
	DesignatorAttribute  DesignatorType = "Attribute" // Deprecated
	/*
		WorkloadID format.
		k8s format: wlid://cluster-<cluster>/namespace-<namespace>/<kind>-<name>
		native format: wlid://datacenter-<datacenter>/project-<project>/native-<name>
	*/
	DesignatorWlid DesignatorType = "Wlid"
	/*
		Wild card - subset of wlid. e.g.
		1. Include cluster:
			wlid://cluster-<cluster>/
		2. Include cluster and namespace (filter out all other namespaces):
			wlid://cluster-<cluster>/namespace-<namespace>/
	*/
	DesignatorWildWlid      DesignatorType = "WildWlid"
	DesignatorWlidContainer DesignatorType = "WlidContainer"
	DesignatorWlidProcess   DesignatorType = "WlidProcess"
	DesignatorSid           DesignatorType = "Sid" // secret id
)

// attributes
const (
	AttributeCluster   = "cluster"
	AttributeNamespace = "namespace"
	AttributeKind      = "kind"
	AttributeName      = "name"
)

// PortalDesignator represented single designation options
type PortalDesignator struct {
	DesignatorType DesignatorType    `json:"designatorType"`
	WLID           string            `json:"wlid"`
	WildWLID       string            `json:"wildwlid"`
	SID            string            `json:"sid"`
	Attributes     map[string]string `json:"attributes"`
}
