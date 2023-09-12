package cautils

type OperatorSubCommand string

const (
	ScanCommand                OperatorSubCommand = "scan"
	ScanConfigCommand          OperatorSubCommand = "config"
	ScanVulnerabilitiesCommand OperatorSubCommand = "vulnerabilities"
)

type OperatorServicesStatus struct {
	ScanConfig          bool
	ScanVulnerabilities bool
}

type VulnerabilitiesScanInfo struct {
	IncludeNamespaces []string
}

type ConfigScanInfo struct {
	Submit             bool
	ExcludedNamespaces []string
	IncludedNamespaces []string
	HostScanner        bool
	Frameworks         []string // Load frameworks for config scan
}

type OperatorInfo struct {
	Subcommands []OperatorSubCommand
	OperatorServicesStatus
	ConfigScanInfo
	VulnerabilitiesScanInfo
}

type OperatorConnector interface {
	StartPortForwarder() error
	StopPortForwarder()
	GetPortForwardLocalhost() string
}
