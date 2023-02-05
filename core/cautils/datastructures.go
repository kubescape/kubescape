package cautils

import (
	"context"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/opa-utils/reporthandling"
	apis "github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/attacktrack/v1alpha1"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/prioritization"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
)

// K8SResources map[<api group>/<api version>/<resource>][]<resourceID>
type K8SResources map[string][]string
type KSResources map[string][]string

type OPASessionObj struct {
	K8SResources          *K8SResources                                 // input k8s objects
	ArmoResource          *KSResources                                  // input ARMO objects
	AllPolicies           *Policies                                     // list of all frameworks
	AllResources          map[string]workloadinterface.IMetadata        // all scanned resources, map[<resource ID>]<resource>
	ResourcesResult       map[string]resourcesresults.Result            // resources scan results, map[<resource ID>]<resource result>
	ResourceSource        map[string]reporthandling.Source              // resources sources, map[<resource ID>]<resource result>
	ResourcesPrioritized  map[string]prioritization.PrioritizedResource // resources prioritization information, map[<resource ID>]<prioritized resource>
	ResourceAttackTracks  map[string]v1alpha1.IAttackTrack              // resources attack tracks, map[<resource ID>]<attack track>
	AttackTracks          map[string]v1alpha1.IAttackTrack
	Report                *reporthandlingv2.PostureReport // scan results v2 - Remove
	RegoInputData         RegoInputData                   // input passed to rego for scanning. map[<control name>][<input arguments>]
	Metadata              *reporthandlingv2.Metadata
	InfoMap               map[string]apis.StatusInfo         // Map errors of resources to StatusInfo
	ResourceToControlsMap map[string][]string                // map[<apigroup/apiversion/resource>] = [<control_IDs>]
	SessionID             string                             // SessionID
	Policies              []reporthandling.Framework         // list of frameworks to scan
	Exceptions            []armotypes.PostureExceptionPolicy // list of exceptions to apply on scan results
	OmitRawResources      bool                               // omit raw resources from output
}

func NewOPASessionObj(ctx context.Context, frameworks []reporthandling.Framework, k8sResources *K8SResources, scanInfo *ScanInfo) *OPASessionObj {
	return &OPASessionObj{
		Report:                &reporthandlingv2.PostureReport{},
		Policies:              frameworks,
		K8SResources:          k8sResources,
		AllResources:          make(map[string]workloadinterface.IMetadata),
		ResourcesResult:       make(map[string]resourcesresults.Result),
		ResourcesPrioritized:  make(map[string]prioritization.PrioritizedResource),
		InfoMap:               make(map[string]apis.StatusInfo),
		ResourceToControlsMap: make(map[string][]string),
		ResourceSource:        make(map[string]reporthandling.Source),
		SessionID:             scanInfo.ScanID,
		Metadata:              scanInfoToScanMetadata(ctx, scanInfo),
		OmitRawResources:      scanInfo.OmitRawResources,
	}
}

func (sessionObj *OPASessionObj) SetMapNamespaceToNumberOfResources(mapNamespaceToNumberOfResources map[string]int) {
	if sessionObj.Metadata.ContextMetadata.ClusterContextMetadata == nil {
		sessionObj.Metadata.ContextMetadata.ClusterContextMetadata = &reporthandlingv2.ClusterMetadata{}
	}
	if sessionObj.Metadata.ContextMetadata.ClusterContextMetadata.MapNamespaceToNumberOfResources == nil {
		sessionObj.Metadata.ContextMetadata.ClusterContextMetadata.MapNamespaceToNumberOfResources = make(map[string]int)
	}
	sessionObj.Metadata.ContextMetadata.ClusterContextMetadata.MapNamespaceToNumberOfResources = mapNamespaceToNumberOfResources
}

func (sessionObj *OPASessionObj) SetNumberOfWorkerNodes(n int) {
	if sessionObj.Metadata.ContextMetadata.ClusterContextMetadata == nil {
		sessionObj.Metadata.ContextMetadata.ClusterContextMetadata = &reporthandlingv2.ClusterMetadata{}
	}
	sessionObj.Metadata.ContextMetadata.ClusterContextMetadata.NumberOfWorkerNodes = n
}

func NewOPASessionObjMock() *OPASessionObj {
	return &OPASessionObj{
		Policies:             nil,
		K8SResources:         nil,
		AllResources:         make(map[string]workloadinterface.IMetadata),
		ResourcesResult:      make(map[string]resourcesresults.Result),
		ResourcesPrioritized: make(map[string]prioritization.PrioritizedResource),
		Report:               &reporthandlingv2.PostureReport{},
		Metadata: &reporthandlingv2.Metadata{
			ScanMetadata: reporthandlingv2.ScanMetadata{
				ScanningTarget: 0,
			},
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
	DataControlInputs    map[string]string   `json:"dataControlInputs"`
	// ClusterName          string              `json:"clusterName"`
	// K8sConfig            RegoK8sConfig       `json:"k8sconfig"`
}

type Policies struct {
	Controls   map[string]reporthandling.Control // map[<control ID>]<control>
	Frameworks []string
}
