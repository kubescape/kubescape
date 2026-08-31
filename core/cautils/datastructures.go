package cautils

import (
	"context"
	"sort"
	"time"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/syft/syft/sbom"
	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/pkg/vapreconcile"
	"github.com/kubescape/opa-utils/reporthandling"
	apis "github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/attacktrack/v1alpha1"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/prioritization"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// K8SResources map[<api group>/<api version>/<resource>][]<resourceID>
type K8SResources map[string][]string
type ExternalResources map[string][]string

// VexStatus represents the evaluated VEX status for a vulnerability.
type VexStatus struct {
	Status        string
	Justification string
}

type ImageScanData struct {
	Context               pkg.Context
	IgnoredMatches        []match.IgnoredMatch
	Image                 string
	Platform              string
	Matches               match.Matches
	Packages              []pkg.Package
	SBOM                  *sbom.SBOM
	VulnerabilityProvider vulnerability.Provider
	VexStatuses           map[string]VexStatus
	// VulnDBBuilt is the build timestamp of the vulnerability DB used for this
	// scan. It lets users (especially air-gapped ones) see how fresh the data
	// was. Nil when the DB status is unknown.
	VulnDBBuilt *time.Time `json:"vulnDBBuilt,omitempty"`
}

// Target identifies the exact image variant represented by these results.
// Existing reports keep their original image spelling when no platform was
// selected, while multi-architecture scans remain distinguishable everywhere
// the image name is used as a label or grouping key.
func (d ImageScanData) Target() string {
	return ImageScanTarget(d.Image, d.Platform)
}

// ImageScanTarget formats an image variant for human-facing output and logs.
// Machine-readable identifiers should keep image and platform in separate
// fields so adding platform awareness does not change existing fingerprints.
func ImageScanTarget(image, platform string) string {
	if platform == "" {
		return image
	}
	return image + " [" + platform + "]"
}

// SkippedManifest records a manifest file that was discovered but could not
// be loaded or identified as a Kubernetes object during scan. It is populated
// at the file-loading layer so the user knows which manifests were not
// evaluated.
type SkippedManifest struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

type ScanTypes string

const (
	TopWorkloadsNumber           = 3
	ScanTypeCluster    ScanTypes = "cluster"
	ScanTypeRepo       ScanTypes = "repo"
	ScanTypeImage      ScanTypes = "image"
	ScanTypeWorkload   ScanTypes = "workload"
	ScanTypeFramework  ScanTypes = "framework"
	ScanTypeControl    ScanTypes = "control"
)

type OPASessionObj struct {
	K8SResources          K8SResources                                  // input k8s objects
	ExternalResources     ExternalResources                             // input non-k8s objects (external resources)
	AllPolicies           *Policies                                     // list of all frameworks
	ExcludedRules         map[string]bool                               // rules to exclude map[rule name>]X
	AllResources          map[string]workloadinterface.IMetadata        // all scanned resources, map[<resource ID>]<resource>
	ResourcesResult       map[string]resourcesresults.Result            // resources scan results, map[<resource ID>]<resource result>
	ResourceSource        map[string]reporthandling.Source              // resources sources, map[<resource ID>]<resource result>
	ResourcesPrioritized  map[string]prioritization.PrioritizedResource // resources prioritization information, map[<resource ID>]<prioritized resource>
	ResourceAttackTracks  map[string][]v1alpha1.IAttackTrack            // resources attack tracks, map[<resource ID>][]<attack track> -- a resource can be implicated by more than one attack track at once, each contributing to its score
	AttackTracks          map[string]v1alpha1.IAttackTrack
	Report                *reporthandlingv2.PostureReport // scan results v2 - Remove
	RegoInputData         RegoInputData                   // input passed to rego for scanning. map[<control name>][<input arguments>]
	Metadata              *reporthandlingv2.Metadata
	InfoMap               map[string]apis.StatusInfo         // Map errors of resources to StatusInfo
	ResourceToControlsMap map[string][]string                // map[<apigroup/apiversion/resource>] = [<control_IDs>]
	ScanCoverage          ScanCoverage                       // runtime coverage gaps (failed GVR pulls + not-evaluated controls)
	PartialGVRFailures    []PartialGVRPull                   // per-selector LIST failures for GVRs that were partially collected
	UnexaminedKinds       []UnexaminedKind                   // cluster-served resource kinds no control in the policy set queried
	PolicyDegradations    []PolicyDegradation                // policy inputs (control configurations, exceptions) served from a fallback
	SkippedManifests      []SkippedManifest                  // manifest files skipped during loading (invalid YAML, missing kind, etc.)
	SessionID             string                             // SessionID
	Policies              []reporthandling.Framework         // list of frameworks to scan
	Exceptions            []armotypes.PostureExceptionPolicy // list of exceptions to apply on scan results
	ExceptionAudit        *ExceptionAudit                    // optional exception usage audit
	AuditExceptions       bool                               // include exception usage audit in supported outputs
	HonorInlineExceptions bool                               // honor kubescape.io/skip-* annotations as inline exception policies
	OmitRawResources      bool                               // omit raw resources from output
	SingleResourceScan    workloadinterface.IWorkload        // single resource scan
	TopWorkloadsByScore   []reporthandling.IResource
	TriggeredByCLI        bool
	LabelsToCopy          []string                    // Labels to copy from workloads to scan reports
	SkipControls          string                      // Comma-separated control IDs to skip
	IncludeControls       string                      // Comma-separated control IDs to include (all others skipped)
	VAPPolicies           []unstructured.Unstructured // ValidatingAdmissionPolicy resources collected from the cluster
	VAPBindings           []unstructured.Unstructured // ValidatingAdmissionPolicyBinding resources collected from the cluster

	// VAPCoverage refines VAPPolicies/VAPBindings' coarse "is any binding
	// present" signal (see reportsummary.ControlSummary.VAPEnforcement) with
	// per-resource binding-scope matching: a control's VAP can be Bound
	// while its binding's namespaceSelector/objectSelector does not actually
	// cover some or all of the resources that failed it. Populated by
	// resultshandling after VAPPolicies/VAPBindings are enriched into the
	// report, keyed by control ID.
	VAPCoverage map[string]*vapreconcile.ControlCoverage

	// EnvVarSecretRefs records, per resource ID and then per container name,
	// which container env var names had a ValueFrom reference
	// (SecretKeyRef/ConfigMapKeyRef/FieldRef/ResourceFieldRef) before
	// updateResults's removeData step clears ValueFrom and overwrites Value.
	// It deliberately holds only the env var name, never the reference
	// target or value, so the anonymizer can still recognize which env var
	// names to anonymize under --hide/--encrypt after the scrub, without the
	// scrub itself retaining anything sensitive.
	//
	// Keyed by container name (unique across containers/initContainers/
	// ephemeralContainers within one pod, enforced by the API server) rather
	// than merged into one per-resource set: two containers in the same pod
	// can have an env var with the same name where only one is
	// reference-backed, and only that container's env var may be
	// anonymized.
	EnvVarSecretRefs map[string]map[string]map[string]struct{}
}

func NewOPASessionObj(ctx context.Context, frameworks []reporthandling.Framework, k8sResources K8SResources, scanInfo *ScanInfo, policyIdentifiers []PolicyIdentifier) *OPASessionObj {
	// Inline annotation exceptions are off by default for live-cluster scans and on by
	// default when scanning local manifests, unless the CLI explicitly sets the flag.
	if scanInfo.HonorInlineExceptions.Get() == nil {
		scanInfo.HonorInlineExceptions.SetBool(len(scanInfo.InputPatterns) > 0)
	}
	clusterSize := max(estimateClusterSize(k8sResources), 100)

	return &OPASessionObj{
		Report:                &reporthandlingv2.PostureReport{},
		Policies:              frameworks,
		K8SResources:          k8sResources,
		AllResources:          make(map[string]workloadinterface.IMetadata, clusterSize),
		ResourcesResult:       make(map[string]resourcesresults.Result, clusterSize),
		ResourcesPrioritized:  make(map[string]prioritization.PrioritizedResource, clusterSize/10),
		InfoMap:               make(map[string]apis.StatusInfo, clusterSize/10),
		ResourceToControlsMap: make(map[string][]string, clusterSize/2),
		ResourceSource:        make(map[string]reporthandling.Source, clusterSize),
		SessionID:             scanInfo.ScanID,
		Metadata:              scanInfoToScanMetadata(ctx, scanInfo, policyIdentifiers),
		OmitRawResources:      scanInfo.OmitRawResources,
		AuditExceptions:       scanInfo.AuditExceptions,
		HonorInlineExceptions: scanInfo.HonorInlineExceptions.GetBool(),
		TriggeredByCLI:        scanInfo.TriggeredByCLI,
		LabelsToCopy:          scanInfo.LabelsToCopy,
		SkipControls:          scanInfo.SkipControls,
		IncludeControls:       scanInfo.IncludeControls,
	}
}

type ExceptionAudit struct {
	Summary   ExceptionAuditSummary `json:"summary"`
	Items     []ExceptionAuditItem  `json:"items"`
	Generated bool                  `json:"generated"`
}

type ExceptionAuditSummary struct {
	Total          int `json:"total"`
	Active         int `json:"active"`
	Expired        int `json:"expired"`
	Matched        int `json:"matched"`
	Unused         int `json:"unused"`
	InvalidControl int `json:"invalidControl"`
}

type ExceptionAuditItem struct {
	Name             string                `json:"name"`
	Status           string                `json:"status"`
	MatchCount       int                   `json:"matchCount"`
	Expired          bool                  `json:"expired,omitempty"`
	InvalidControls  []string              `json:"invalidControls,omitempty"`
	ControlIDs       []string              `json:"controlIDs,omitempty"`
	MatchedResources []ExceptionAuditMatch `json:"matchedResources,omitempty"`
}

type ExceptionAuditMatch struct {
	ResourceID string `json:"resourceID"`
	Kind       string `json:"kind,omitempty"`
	Namespace  string `json:"namespace,omitempty"`
	Name       string `json:"name,omitempty"`
	ControlID  string `json:"controlID"`
	RuleName   string `json:"ruleName,omitempty"`
}

func estimateClusterSize(k8sResources K8SResources) int {
	total := 0
	for _, resourceIDs := range k8sResources {
		total += len(resourceIDs)
	}
	return total
}

// SetTopWorkloads sets the top workloads by score
func (sessionObj *OPASessionObj) SetTopWorkloads() {
	topWorkloadsSorted := make([]prioritization.PrioritizedResource, 0)

	// create list in order to sort
	for _, wl := range sessionObj.ResourcesPrioritized {
		topWorkloadsSorted = append(topWorkloadsSorted, wl)
	}

	// sort by score. If scores are equal, sort by resource ID
	sort.Slice(topWorkloadsSorted, func(i, j int) bool {
		if topWorkloadsSorted[i].Score == topWorkloadsSorted[j].Score {
			return topWorkloadsSorted[i].ResourceID < topWorkloadsSorted[j].ResourceID
		}
		return topWorkloadsSorted[i].Score > topWorkloadsSorted[j].Score
	})

	if sessionObj.Report == nil {
		sessionObj.Report = &reporthandlingv2.PostureReport{}
	}

	// set top workloads according to number of top workloads
	topWorkloads := make([]reporthandling.IResource, 0, TopWorkloadsNumber)
	for _, wl := range topWorkloadsSorted {
		if len(topWorkloads) >= TopWorkloadsNumber {
			break
		}

		source := sessionObj.ResourceSource[wl.ResourceID]

		res, ok := sessionObj.AllResources[wl.ResourceID]
		if !ok {
			logger.L().Debug("resource missing from AllResources, skipping",
				helpers.String("resourceID", wl.ResourceID))
			continue
		}
		wlObj := &reporthandling.Resource{
			IMetadata: res,
			Source:    &source,
		}

		topWorkloads = append(topWorkloads, wlObj)
	}

	sessionObj.TopWorkloadsByScore = topWorkloads
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
