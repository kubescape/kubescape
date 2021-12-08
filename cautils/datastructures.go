package cautils

import (
	"github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/k8s-interface/workloadinterface"
	"github.com/armosec/opa-utils/reporthandling"
)

// K8SResources map[<api group>/<api version>/<resource>][]<resourceID>
type K8SResources map[string][]string

type OPASessionObj struct {
	K8SResources  *K8SResources                          // input k8s objects
	Frameworks    []reporthandling.Framework             // list of frameworks to scan
	AllResources  map[string]workloadinterface.IMetadata // all scanned resources, map[<rtesource ID>]<resource>
	PostureReport *reporthandling.PostureReport          // scan results
	Exceptions    []armotypes.PostureExceptionPolicy     // list of exceptions to apply on scan results
	RegoInputData RegoInputData                          // input passed to rgo for scanning. map[<control name>][<input arguments>]
}

func NewOPASessionObj(frameworks []reporthandling.Framework, k8sResources *K8SResources) *OPASessionObj {
	return &OPASessionObj{
		Frameworks:   frameworks,
		K8SResources: k8sResources,
		AllResources: make(map[string]workloadinterface.IMetadata),
		PostureReport: &reporthandling.PostureReport{
			ClusterName:  ClusterName,
			CustomerGUID: CustomerGUID,
		},
	}
}

func NewOPASessionObjMock() *OPASessionObj {
	return &OPASessionObj{
		Frameworks:   nil,
		K8SResources: nil,
		AllResources: make(map[string]workloadinterface.IMetadata),
		PostureReport: &reporthandling.PostureReport{
			ClusterName:  "",
			CustomerGUID: "",
			ReportID:     "",
			JobID:        "",
		},
	}
}

type ComponentConfig struct {
	Exceptions Exception `json:"exceptions"`
}

type Exception struct {
	Ignore        *bool                      `json:"ignore"`        // ignore test results
	MultipleScore *reporthandling.AlertScore `json:"multipleScore"` // MultipleScore number - float32
	Namespaces    []string                   `json:"namespaces"`
	Regex         string                     `json:"regex"` // not supported
}

type RegoInputData struct {
	PostureControlInputs map[string][]string `json:"postureControlInputs"`
	// ClusterName          string              `json:"clusterName"`
	// K8sConfig            RegoK8sConfig       `json:"k8sconfig"`
}
