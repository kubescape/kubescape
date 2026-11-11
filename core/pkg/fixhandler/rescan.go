package fixhandler

// ScanRoots returns the directories the report's manifests were read from, the
// roots a rescan has to read them through to get the resource IDs the report
// gave them: a local resource's ID depends on its path relative to its root, so
// the same file read through another root is another resource. A scan inside a
// git repository has one, the repository root, however many inputs it had. It
// covers every manifest the scan read, not only the ones that were fixed.
func (h *FixHandler) ScanRoots() []string {
	return h.scanRoots()
}

// RecordedControlsInputs returns the controls configuration file the scan that
// made the report was given, as the report records it, or "" when the report
// does not name one. It is the only scan setting that part of the report keeps:
// the exceptions it used, the controls version and where its policies came from
// are not recorded.
func (h *FixHandler) RecordedControlsInputs() string {
	if h.reportObj == nil {
		return ""
	}
	return h.reportObj.Metadata.ScanMetadata.ControlsInputs
}

// RecordedKubescapeVersion returns the Kubescape version that made the report,
// or "" when it does not say. The policies a scan evaluates change between
// releases, so a rescan by another version can judge a control differently.
func (h *FixHandler) RecordedKubescapeVersion() string {
	if h.reportObj == nil {
		return ""
	}
	return h.reportObj.Metadata.ScanMetadata.KubescapeVersion
}
