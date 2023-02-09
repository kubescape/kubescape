package reporter

// SubmitContext specifies the analysis context used to produce a posture report.
type SubmitContext string

const (
	SubmitContextScan       SubmitContext = "scan"
	SubmitContextRBAC       SubmitContext = "rbac"
	SubmitContextRepository SubmitContext = "repository"
)

func (c SubmitContext) String() string {
	return string(c)
}
