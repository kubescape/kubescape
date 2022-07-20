package docs

// swagger:route POST /v1/metrics metrics enableMetrics
// Trigger Kubescape support for Prometheus
//
// Enables support for Prometheus metrics.
//
// Responses:
// 200: enableMetricsResponse

type enableMetricsResponse struct{}

// swagger:response enableMetricsResponse
type enableMetricsResponseWrapper struct {
	// in:body
	Body enableMetricsResponse
}

// swagger:route POST /v1/scan scanning triggerScan
// Trigger a kubescape scan.
//
// The server will return an ID and will execute the scanning asynchronously.
//
// Responses:
//   200: triggerScanResponse

// swagger:enum TriggerScanTargetType
type TriggerScanTargetType string

const (
	Framework TriggerScanTargetType = "framework"
	Control   TriggerScanTargetType = "control"
)

type triggerScanParams struct {
	// Results format. Same as `kubescape scan --format`
	//
	// default: json
	// example: json
	Format string `json:"format"`
	// List of namespaces to exclude. Same as `kubescape scan --excluded-namespaces`
	//
	// example: ["kube-system", "armo-system"]
	ExcludedNamespaces []string `json:"excludedNamespaces"`
	// List of namespaces to include. Same as `kubescape scan --include-namespaces`
	//
	// example: ["litmus-tests", "known-bad"]
	IncludeNamespaces []string `json:"includeNamespaces"`
	// Use the cached artifacts instead of downloading (offline support)
	//
	// example: false
	UseCachedArtifacts bool `json:"useCachedArtifacts"`
	// Submit results to Kubescape Cloud. Same as `kubescape scan --submit`.
	//
	// example: true
	Submit bool `json:"submit"`
	// Deploy Kubescape K8s host-scanner DeamonSet in the scanned cluster (same as `kubescape scan --enable-host-scan`)
	//
	// example: true
	HostScanner bool `json:"hostScanner"`
	// Do not submit results to Kubescape Cloud.
	//
	// Same as `kubescape scan --keep-local`
	KeepLocal bool `json:"keepLocal"`
	// A Kubescape account ID to use for scanning.
	//
	// Same as `kubescape scan --account`.
	// example: NewGuid()
	Account string `json:"account"`
	// Type of the scan target: either `framework` or `control`.
	//
	// example: framework
	TargetType TriggerScanTargetType `json:"targetType"`
	// Name of the scan targets.
	//
	// For example, if you select `targetType: "framework"`, you can trigger a scan using the NSA and MITRE ATT&CK Framework by passing `targetNames: ["nsa, "mitre"]`.
	// example: ["nsa", "mitre"]
	TargetNames []string `json:"targetNames"`
}

// swagger:parameters triggerScan
type triggerScanParamsWrapper struct {
	// Trigger scan parameters
	// in:body
	Body triggerScanParams
	// Whether to wait for the result to complete.
	//
	// Triggers a synchronous scan. A synchronous scan returns the Scan results, and not a scan ID. Use synchronous scanning only in small clusters or with an increased timeout
	//
	// default: false
	Wait bool `json:"wait"`
	// Keep the results in local storage after returning.
	//
	// default: false
	Keep bool `json:"keep"`
}

// swagger:enum ScanResponseType
type ScanResponseType string

const (
	V1Results ScanResponseType = "v1results"
	Busy      ScanResponseType = "busy"
	NotBusy   ScanResponseType = "notBusy"
	Ready     ScanResponseType = "ready"
	Error     ScanResponseType = "error"
)

type triggerScanResponse struct {
	// ID of the performed scan
	Id string `json:"id"`
	// Type of the response object
	Type ScanResponseType `json:"type"`
	// Response payload as list of bytes
	Response interface{} `json:"response"`
}

// The triggerScan response object
// swagger:response triggerScanResponse
type triggerScanResponseWrapper struct {
	// in:body
	Body triggerScanResponse
}

// swagger:route GET /v1/results/{scanID} scanning getScanResults
// Read results of a previously performed scan.
//
// Responses:
//   200: getScanResultsResponse


// swagger:parameters getScanResults
type getScanResultsRequestWrapper struct {
	// in:path
	ScanID string `json:"scanID"`
}

type getScanResultsResponse struct {
	ID       string      `json:"id"`
	Type     string      `json:"type"`
	Response interface{} `json:"response"`
}

// swagger:response
type getScanResultsResponseWrapper struct {
	// in:body
	Body getScanResultsResponse
}
