package getter

// NativeFrameworks identifies all pre-built, native frameworks.
var NativeFrameworks = []string{"allcontrols", "nsa", "mitre"}

// SecurityViewFrameworks identifies the frameworks the default security view of
// `kubescape scan` evaluates on top of NativeFrameworks: workloadscan for a path
// and clusterscan for a cluster. The regolibrary types them as security rather
// than compliance frameworks, so a framework listing leaves them out and they
// have to be requested by name.
var SecurityViewFrameworks = []string{"workloadscan", "clusterscan"}
