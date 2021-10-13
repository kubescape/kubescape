package cautils

import (
	"github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/armoapi-go/opapolicy"
)

// K8SResources map[<api group>/<api version>/<resource>]<resource object>
type K8SResources map[string]interface{}

type OPASessionObj struct {
	Frameworks    []opapolicy.Framework
	K8SResources  *K8SResources
	Exceptions    []armotypes.PostureExceptionPolicy
	PostureReport *opapolicy.PostureReport
}

func NewOPASessionObj(frameworks []opapolicy.Framework, k8sResources *K8SResources) *OPASessionObj {
	return &OPASessionObj{
		Frameworks:   frameworks,
		K8SResources: k8sResources,
		PostureReport: &opapolicy.PostureReport{
			ClusterName:  ClusterName,
			CustomerGUID: CustomerGUID,
		},
	}
}

func NewOPASessionObjMock() *OPASessionObj {
	return &OPASessionObj{
		Frameworks:   nil,
		K8SResources: nil,
		PostureReport: &opapolicy.PostureReport{
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
	Ignore        *bool                 `json:"ignore"`        // ignore test results
	MultipleScore *opapolicy.AlertScore `json:"multipleScore"` // MultipleScore number - float32
	Namespaces    []string              `json:"namespaces"`
	Regex         string                `json:"regex"` // not supported
}
