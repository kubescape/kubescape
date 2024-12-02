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

// CalculateFixed calculates the number of fixes in a given list of FixedIn objects.
//
// Example Usage:
//
//	fixes := []FixedIn{
//	  {Version: "None"},
//	  {Version: "1.2.3"},
//	  {Version: ""},
//	}
//
// result := CalculateFixed(fixes)
// fmt.Println(result) // Output: 1
//
// Inputs:
// - Fixes: a slice of FixedIn objects representing the fixes for a vulnerability.
//
// Flow:
// 1. Iterate over each FixedIn object in the Fixes slice.
// 2. Check if the Version field of the current FixedIn object is not equal to "None" and not empty.
// 3. If the condition is true for any FixedIn object, return 1.
// 4. If the loop completes without returning, return 0.
//
// Outputs:
// - An integer representing the number of fixes found in the Fixes slice.
func CalculateFixed(Fixes []FixedIn) int {
	for _, fix := range Fixes {
		if fix.Version != "None" && fix.Version != "" {
			return 1
		}
	}
	return 0
}
