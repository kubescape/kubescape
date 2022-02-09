package containerscan

const (
	//defines Relevancy as enum-like
	Unknown   = "Unknown"
	Relevant  = "Relevant"
	Irelevant = "Irelevant"
	NoSP      = "No signature profile to compare"

	//Clair Severities
	UnknownSeverity    = "Unknown"
	NegligibleSeverity = "Negligible"
	LowSeverity        = "Low"
	MediumSeverity     = "Medium"
	HighSeverity       = "High"
	CriticalSeverity   = "Critical"

	ContainerScanRedisPrefix = "_containerscan"
)

var KnownSeverities = map[string]bool{
	UnknownSeverity:    true,
	NegligibleSeverity: true,
	LowSeverity:        true,
	MediumSeverity:     true,
	HighSeverity:       true,
	CriticalSeverity:   true,
}

func CalculateFixed(Fixes []FixedIn) int {
	for _, fix := range Fixes {
		if fix.Version != "None" && fix.Version != "" {
			return 1
		}
	}
	return 0
}
