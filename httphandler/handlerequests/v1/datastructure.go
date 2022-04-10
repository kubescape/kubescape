package v1

import (
	"github.com/armosec/kubescape/v2/core/cautils"
	"github.com/armosec/opa-utils/reporthandling"
)

type PostScanRequest struct {
	Format             string                                 `json:"format"`             // Format results (table, json, junit ...) - default json
	Account            string                                 `json:"account"`            // account ID
	Logger             string                                 `json:"-"`                  // logger level - debug/info/error - default is debug
	FailThreshold      float32                                `json:"failThreshold"`      // Failure score threshold
	ExcludedNamespaces []string                               `json:"excludedNamespaces"` // used for host scanner namespace
	IncludeNamespaces  []string                               `json:"includeNamespaces"`  // DEPRECATED?
	TargetNames        []string                               `json:"targetNames"`        // default is all
	TargetType         *reporthandling.NotificationPolicyKind `json:"targetType"`         // framework/control - default is framework
	Submit             cautils.BoolPtrFlag                    `json:"submit"`             // Submit results to Armo BE - default will
	HostScanner        cautils.BoolPtrFlag                    `json:"hostScanner"`        // Deploy ARMO K8s host scanner to collect data from certain controls
	KeepLocal          cautils.BoolPtrFlag                    `json:"keepLocal"`          // Do not submit results
	UseCachedArtifacts cautils.BoolPtrFlag                    `json:"useCachedArtifacts"` // Use the cached artifacts instead of downloading
	// UseExceptions      string      // Load file with exceptions configuration
	// ControlsInputs     string      // Load file with inputs for controls
	// VerboseMode        bool        // Display all of the input resources and not only failed resources
}
