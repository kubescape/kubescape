package v1

type FixInfo struct {
	ReportFile     string // path to report file (mandatory)
	NoConfirm      bool   // if true, no confirmation will be given to the user before applying the fix
	SkipUserValues bool   // if true, user values will not be changed
	DryRun         bool   // if true, no changes will be applied
	// BasePath, if set, restricts fixes to this directory: the report's own
	// recorded scan location (which the report itself controls) must resolve
	// inside it, or NewFixHandler refuses to proceed. Use this when the
	// report file comes from a source you don't fully trust (e.g. a shared
	// CI artifact) - without it, the report's recorded location is trusted
	// as-is, as it always has been.
	BasePath string
}
