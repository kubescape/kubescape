package v1

type DiffInfo struct {
	BaseFile          string // path to base scan JSON report
	HeadFile          string // path to head scan JSON report
	Format            string // output format: "pretty-printer" or "json"
	Output            string // output file path; empty means stdout
	FailOnNew         bool   // exit code 1 when new failures are found
	SeverityThreshold string // only count failures at or above this severity when enforcing --fail-on-new
}
