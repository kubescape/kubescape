package v1

type FixInfo struct {
	ReportFile     string // path to report file (mandatory)
	NoConfirm      bool   // if true, no confirmation will be given to the user before applying the fix
	SkipUserValues bool   // if true, user values will not be changed
	DryRun         bool   // if true, no changes will be applied
}
