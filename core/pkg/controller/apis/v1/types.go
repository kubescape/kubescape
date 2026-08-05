package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +groupName=kubescape.io
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced

// ScanRequest is the Schema for the scanrequests API.
type ScanRequest struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ScanRequestSpec   `json:"spec,omitempty"`
	Status ScanRequestStatus `json:"status,omitempty"`
}

// +kubebuilder:object:generate=true
type ScanRequestSpec struct {
	// +kubebuilder:validation:Enum=cluster;workload;repo;image
	ScanType ScanType `json:"scanType"`

	// +optional
	Frameworks []string `json:"frameworks,omitempty"`

	// +optional
	ScanAll bool `json:"scanAll,omitempty"`

	// +optional
	ExcludedNamespaces []string `json:"excludedNamespaces,omitempty"`

	// +optional
	IncludeNamespaces []string `json:"includeNamespaces,omitempty"`

	// +optional
	HostScanner bool `json:"hostScanner,omitempty"`

	// +optional
	ScanImages bool `json:"scanImages,omitempty"`

	// +kubebuilder:default="10m"
	// +optional
	Timeout *metav1.Duration `json:"timeout,omitempty"`

	// +optional
	TTLSecondsAfterFinished *int32 `json:"ttlSecondsAfterFinished,omitempty"`
}

// +kubebuilder:object:generate=true
type ScanRequestStatus struct {
	// +kubebuilder:validation:Enum=Pending;Running;Succeeded;Failed
	// +optional
	Phase ScanPhase `json:"phase,omitempty"`

	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// +optional
	StartTime *metav1.Time `json:"startTime,omitempty"`

	// +optional
	CompletionTime *metav1.Time `json:"completionTime,omitempty"`

	// +optional
	ResultCount int `json:"resultCount,omitempty"`
}

type ScanPhase string

const (
	ScanPhasePending   ScanPhase = "Pending"
	ScanPhaseRunning   ScanPhase = "Running"
	ScanPhaseSucceeded ScanPhase = "Succeeded"
	ScanPhaseFailed    ScanPhase = "Failed"
)

type ScanType string

const (
	ScanTypeCluster  ScanType = "cluster"
	ScanTypeWorkload ScanType = "workload"
	ScanTypeRepo     ScanType = "repo"
	ScanTypeImage    ScanType = "image"
)

// +kubebuilder:object:root=true

// ScanRequestList contains a list of ScanRequest
type ScanRequestList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ScanRequest `json:"items"`
}

// --- ScanResult ---

// +groupName=kubescape.io
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced

// ScanResult is the Schema for the scanresults API.
// It stores the summarized outcome of a completed ScanRequest.
type ScanResult struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ScanResultSpec   `json:"spec,omitempty"`
	Status ScanResultStatus `json:"status,omitempty"`
}

// ScanResultSpec defines the inputs that produced this result.
// +kubebuilder:object:generate=true
type ScanResultSpec struct {
	// ScanRequestRef points to the ScanRequest that generated this result.
	ScanRequestRef string `json:"scanRequestRef"`
}

// ScanResultStatus defines the observed findings.
// +kubebuilder:object:generate=true
type ScanResultStatus struct {
	// TotalControls is the number of controls evaluated.
	TotalControls int `json:"totalControls"`
	// FailedControls is the number of controls that failed.
	FailedControls int `json:"failedControls"`
	// SeveritySummary breaks down the findings by severity.
	SeveritySummary map[string]int `json:"severitySummary,omitempty"`
	// CompletionTime is when the scan finished.
	CompletionTime *metav1.Time `json:"completionTime,omitempty"`
}

// +kubebuilder:object:root=true

// ScanResultList contains a list of ScanResult
type ScanResultList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ScanResult `json:"items"`
}

// --- ScanSchedule ---

// +groupName=kubescape.io
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced

// ScanSchedule is the Schema for the scanschedules API.
// It acts like a CronJob for ScanRequests.
type ScanSchedule struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ScanScheduleSpec   `json:"spec,omitempty"`
	Status ScanScheduleStatus `json:"status,omitempty"`
}

// ScanScheduleSpec defines the desired scheduling state.
// +kubebuilder:object:generate=true
type ScanScheduleSpec struct {
	// Schedule is a Cron-formatted string (e.g., "0 0 * * *").
	Schedule string `json:"schedule"`

	// Suspend allows pausing the schedule without deleting it.
	// +optional
	Suspend *bool `json:"suspend,omitempty"`

	// Template defines the ScanRequest to create when the schedule fires.
	Template ScanRequestSpec `json:"template"`
}

// ScanScheduleStatus defines the observed scheduling state.
// +kubebuilder:object:generate=true
type ScanScheduleStatus struct {
	// LastScheduleTime tracks the last time a ScanRequest was successfully created.
	// +optional
	LastScheduleTime *metav1.Time `json:"lastScheduleTime,omitempty"`
}

// +kubebuilder:object:root=true

// ScanScheduleList contains a list of ScanSchedule
type ScanScheduleList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ScanSchedule `json:"items"`
}

// --- ScanPolicy ---

// +groupName=kubescape.io
// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Cluster

// ScanPolicy is the Schema for the scanpolicies API.
// It defines cluster-wide defaults and enforcement rules for scans.
type ScanPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec ScanPolicySpec `json:"spec,omitempty"`
}

// ScanPolicySpec defines the default behaviors.
// +kubebuilder:object:generate=true
type ScanPolicySpec struct {
	// DefaultFrameworks defines the fallback frameworks if a ScanRequest omits them.
	// +optional
	DefaultFrameworks []string `json:"defaultFrameworks,omitempty"`

	// MaxConcurrentScans prevents overloading the cluster.
	// +kubebuilder:default=3
	// +optional
	MaxConcurrentScans *int32 `json:"maxConcurrentScans,omitempty"`
}

// +kubebuilder:object:root=true

// ScanPolicyList contains a list of ScanPolicy
type ScanPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ScanPolicy `json:"items"`
}
