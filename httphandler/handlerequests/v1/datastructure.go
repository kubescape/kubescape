package v1

type PostScanRequest struct {
	Format             string   `json:"format"`             // Format results (table, json, junit ...) - default json
	ExcludedNamespaces []string `json:"excludedNamespaces"` // used for host sensor namespace
	IncludeNamespaces  []string `json:"includeNamespaces"`  // DEPRECATED?
	FailThreshold      uint16   `json:"failThreshold"`      // Failure score threshold
	Submit             bool     `json:"submit"`             // Submit results to Armo BE - default will
	HostSensor         bool     `json:"hostSensor"`         // Deploy ARMO K8s host sensor to collect data from certain controls
	KeepLocal          bool     `json:"keepLocal"`          // Do not submit results
	Account            string   `json:"account"`            // account ID
	Logger             string   `json:"-"`                  // logger level - debug/info/error - default is debug
	TargetType         string   `json:"-"`                  // framework/control - default is framework
	TargetNames        []string `json:"-"`                  // default is all
	// UseExceptions      string      // Load file with exceptions configuration
	// ControlsInputs     string      // Load file with inputs for controls
	// VerboseMode        bool        // Display all of the input resources and not only failed resources
}
