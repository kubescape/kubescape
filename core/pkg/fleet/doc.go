// Package fleet turns the per-cluster results of a multi-context scan into a
// single cross-cluster view.
//
// # The problem
//
// Kubescape scans one cluster per invocation, and nothing in the codebase sits
// above a single reporthandlingv2.PostureReport. Every printer, the compliance
// score and ScanCoverage are all shaped around one cluster.
//
// Scanning several contexts is already possible: --kube-contexts loops them
// sequentially and writes one report per context to a context-suffixed output
// path. What it does not do, deliberately, is combine them. Ten contexts
// produce ten independent report files.
//
// That leaves the questions an operator actually asks unanswered. "Which of my
// clusters fail C-0016" and "staging passes this control and prod fails it, so
// where did we drift" both require reading every report and correlating them by
// hand. This package is that correlation, written and tested once, rather than
// re-implemented per organisation in a shell script.
//
// # Where this sits
//
// The input is []ClusterResult: results that have already been collected. This
// package does not scan, does not talk to a cluster, and does not touch the
// scan path. core.Scan, PostureReport and every existing printer are unchanged
// by it, and deleting this directory leaves the single-cluster CLI byte for
// byte identical.
//
// Taking already-collected results rather than driving the scan is what makes
// the whole aggregation testable with no cluster involved. Every function here
// runs against fixtures.
//
// # Design decisions
//
// Four choices are not obvious from the types alone, and each exists because
// the obvious alternative produces a report that quietly misleads.
//
// Skipped and not-evaluated are kept apart. Upstream, a control that could not
// be evaluated and a control that was skipped on purpose are both recorded as
// apis.StatusSkipped, and only the sub-status separates them.
// OPAProcessor.markControlsSkipped is where that pairing is written. Inside one
// cluster the collapse is harmless. Across clusters it is not: two skipped
// controls genuinely agree with each other, whereas a control that one cluster
// evaluated and another did not is a gap in what was measured rather than a
// difference in posture. CellStatus splits the two at the bottom of the stack,
// because a distinction lost on the first hop cannot be recovered later by
// anything reading the matrix.
//
// A cluster that was not scanned keeps its row. It appears in Clusters with its
// status and its error preserved verbatim, and contributes no cells to the
// matrix. Dropping it would produce a report that looks complete and is not,
// which is worse than one that is visibly missing a cluster.
//
// Measurements that were never taken are absent, not zero. ComplianceScore and
// Coverage are pointers so an unscanned cluster serialises without them. Plain
// value types would emit "complianceScore": 0 beside a zeroed coverage block,
// which reads as "fully non-compliant and fully unmeasured" rather than "never
// measured", and would drag down anything averaging the column. The same
// instinct runs through the rest of the aggregation: an absence of evidence is
// never reported as evidence of a problem.
//
// Cluster outcomes are four values, not two. A pipeline responds differently to
// each. Unreachable is an infrastructure condition and may be worth retrying,
// error means the scan ran and something inside it failed, and cancelled means
// the run was interrupted so nothing was learned about that cluster at all. A
// single "failed" value would force every consumer to parse error strings to
// tell those apart, which is the ambiguity a machine-readable report exists to
// remove.
//
// # Determinism
//
// Control summaries live in a map, so BuildControlMatrix sorts its rows by
// control ID. Without that, row order would follow Go's randomised map
// iteration and two reports of an unchanged fleet would not compare equal. A
// fleet report that cannot be diffed against its own previous run is of little
// use in CI, so the sort has a test that runs twenty iterations rather than
// relying on one lucky ordering.
//
// # Per-cluster isolation
//
// Scanning several clusters in one process is only correct because
// cautils.EnterClusterContext re-points the process-global Kubernetes client at
// each context and restores the previous one on the way out. That work landed
// separately and ships its own tests, so this package does not duplicate them.
//
// What it does guard is the half the aggregation reads directly. Control
// evaluation resolves resources through the API-group snapshot, so
// TestDiscoveryRefreshFollowsTheScannedCluster pins the property that the
// snapshot follows the cluster currently being scanned. If a future
// k8s-interface bump reintroduces the early return that once made the snapshot
// sticky, that test fails here rather than surfacing later as a fleet report
// quietly describing the wrong cluster.
//
// # The rollup
//
// BuildComplianceRollup averages the clusters that were measured well enough to
// speak for themselves and names every cluster it left out, because a single
// number standing for a fleet is only honest if the reader can see its basis.
// Two decisions in it are worth stating.
//
// Clusters are weighted equally rather than by size. The question a fleet score
// answers is how compliant the clusters are, not how compliant the resources
// are, and weighting by resource count would let one large cluster speak for
// every other.
//
// A framework's score is skipped wherever it was vacuous, which is to say
// wherever it reported 100% only because every control in it was irrelevant.
// Kubescape already detects that per cluster, in ScanCoverage.VacuousFrameworks.
// Folding such a result into a fleet average would raise the fleet's apparent
// standing on the strength of nothing having been checked, which is the same
// mistake, one level up, that keeping skipped apart from not-evaluated avoids.
//
// # Not here yet
//
//   - Cross-cluster divergence, which compares each control's cell between
//     clusters and reports a difference in posture separately from a gap in
//     what was measured. It reads the matrix built here, so the matrix settles
//     first.
//
//     Deliberately not called drift. Since --baseline landed, drift means
//     comparing one cluster against a report saved earlier, which is a
//     question about time rather than about the fleet. Reusing the word would
//     leave two different comparisons sharing a name.
//
//   - Printers for the aggregate. The wiring exists: --fleet-report on a
//     --kube-contexts scan writes the FleetReport as JSON, and that is the
//     only format so far.
//
//   - Concurrency. Contexts are scanned one at a time because k8sinterface's
//     process-global connection state has no locking around it, so two scans
//     running concurrently would race on that state regardless of
//     EnterClusterContext, which only makes sequential context switches safe.
//     Tracked in https://github.com/kubescape/kubescape/issues/2004.
package fleet
