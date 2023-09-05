package cautils

type OperatorSubCommand string

const (
	ScanCommand                OperatorSubCommand = "scan"
	ScanConfigCommand          OperatorSubCommand = "config"
	ScanVulnerabilitiesCommand OperatorSubCommand = "vulnerabilities"
)

type VulnerabilitiesScanInfo struct {
	IncludeNamespaces []string
}

type ConfigScanInfo struct {
	ScanInfo
	Frameworks []string // Load frameworks for config scan
}

type OperatorInfo struct {
	Subcommands []OperatorSubCommand
	ConfigScanInfo
	VulnerabilitiesScanInfo
}
