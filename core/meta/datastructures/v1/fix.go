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
	BasePath             string
	ContainerProfilePath string // Path to an optional ContainerProfile JSON file
	// IncludeControls and SkipControls narrow which failed controls are
	// remediated. Matching is case-insensitive on the control ID, and
	// SkipControls wins over IncludeControls, mirroring the scan-side
	// --include-controls/--skip-controls pair.
	IncludeControls []string
	SkipControls    []string
	// OutputDir, when set, receives the fixes instead of their default
	// destination. For a file-based report that default is the manifests
	// themselves: with OutputDir the fixed copies are written there, mirroring
	// the scanned tree, and the originals are left untouched. For a cluster scan
	// report, which has no manifests to rewrite, one patched manifest per
	// resource is written there instead of being printed to stdout.
	OutputDir string
}
