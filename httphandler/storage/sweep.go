package storage

import (
	"context"
	stderrors "errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	v2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const sweepListPageSize = 500

// rbacGVRs are the resources a ServiceAccount, Role and binding record is
// built from. If the scan listed one of them only in part, the report can lack
// a binding that still exists.
var rbacGVRs = []string{
	"/v1/serviceaccounts",
	"rbac.authorization.k8s.io/v1/roles",
	"rbac.authorization.k8s.io/v1/rolebindings",
	"rbac.authorization.k8s.io/v1/clusterroles",
	"rbac.authorization.k8s.io/v1/clusterrolebindings",
}

// SweepOrphanedPostureResults deletes the WorkloadConfigurationScanSummary
// objects, and the WorkloadConfigurationScan of the same name, that a completed
// cluster-wide scan no longer vouches for.
//
// Storage cleanup removes these records only for Pods and the workload kinds,
// so a record for a deleted Node, Secret, PersistentVolume, RBAC object and so
// on stays forever with its last verdict (kubescape/storage#432). The scanner
// is the component that knows what it just scanned, so it sweeps here.
//
// A record is deleted only when all of the following hold:
//   - this report did not write it: its report-created-at annotation is older
//     than the report, or absent;
//   - this report evaluated every control the record carries, so a scan with a
//     different framework set leaves records of other frameworks alone;
//   - its object namespace was in the scan scope;
//   - the scan listed the record's kind in full: at least one LIST of its
//     resource had no rule field selector, and no LIST of it failed or was
//     partial. A ServiceAccount, Role and binding record needs each RBAC
//     resource in rbacGVRs that the scan listed to be listed in full.
//
// Storage ignores delete preconditions today, so a record that another scan
// rewrites between the Get and the Delete is lost until the next scan writes it
// again. The scanner runs one scan at a time and the sweep runs inside that
// scan, so only a second scanner, for example a terminating pod during a
// rollout, can do that. The caller therefore runs the sweep only when
// KS_SWEEP_ORPHANED_POSTURE_RESULTS opts in.
//
// Call it only after StorePostureReportResults returned nil, so that every
// result of the report carries the report timestamp.
func (a *APIServerStore) SweepOrphanedPostureResults(ctx context.Context, pr *v2.PostureReport, collection Collection) error {
	if pr == nil || pr.ReportGenerationTime.IsZero() {
		return nil
	}
	scanMetadata := pr.Metadata.ScanMetadata
	if scanMetadata.ScanningTarget != v2.Cluster || len(scanMetadata.IncludeNamespaces) > 0 {
		return nil
	}

	evaluated := evaluatedControlIDs(pr)
	if len(evaluated) == 0 {
		return nil
	}
	collected, ok := newCollectedKinds(collection)
	if !ok {
		return nil
	}

	candidates, err := a.listUnrefreshedSummaries(ctx, pr)
	if err != nil {
		return fmt.Errorf("failed to list workload configuration scan summaries: %w", err)
	}

	scope := sweepScope{
		reportTime: pr.ReportGenerationTime,
		excluded:   scanMetadata.ExcludedNamespaces,
		collected:  collected,
		evaluated:  evaluated,
	}
	deleted := 0
	var errs []error
	for i := range candidates {
		candidate := &candidates[i]
		if !scope.inScope(candidate.ObjectMeta) {
			continue
		}
		ok, err := a.deleteIfOrphaned(ctx, pr, scope, candidate)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s/%s: %w", candidate.Namespace, candidate.Name, err))
			continue
		}
		if ok {
			deleted++
		}
	}

	if deleted > 0 {
		logger.L().Ctx(ctx).Info("deleted posture records that the latest scan no longer reports",
			helpers.Int("deleted", deleted))
	}
	return stderrors.Join(errs...)
}

// evaluatedControlIDs returns the controls this report actually evaluated. A
// skipped control (missing input, manual review, disabled) vouches for nothing.
func evaluatedControlIDs(pr *v2.PostureReport) map[string]struct{} {
	evaluated := make(map[string]struct{}, len(pr.SummaryDetails.Controls))
	for id, control := range pr.SummaryDetails.Controls {
		if control.GetStatus().Status() == apis.StatusSkipped {
			continue
		}
		evaluated[id] = struct{}{}
	}
	return evaluated
}

// Collection is what a scan listed, in the group/version/resource form of the
// scan coverage.
type Collection struct {
	// Listed maps each queried resource to whether at least one LIST of it had
	// no rule field selector.
	Listed map[string]bool
	// Incomplete are the resources whose LIST failed or was partial. A
	// "discovery:<group/version>" entry covers a whole group, and
	// "discovery:*" every resource.
	Incomplete []string
}

// collectedKinds tells which records a scan can judge from what it listed. It
// compares group and resource only, because discovery can prefer another
// version than the one a rule queried.
type collectedKinds struct {
	listed     map[string]bool
	incomplete map[string]struct{}
	groups     map[string]struct{}
}

// newCollectedKinds returns false when discovery failed altogether, so that no
// kind is known to be listed in full.
func newCollectedKinds(collection Collection) (collectedKinds, bool) {
	c := collectedKinds{
		listed:     make(map[string]bool, len(collection.Listed)),
		incomplete: make(map[string]struct{}),
		groups:     make(map[string]struct{}),
	}
	for gvr, full := range collection.Listed {
		key := groupResource(gvr)
		c.listed[key] = c.listed[key] || full
	}
	for _, gvr := range collection.Incomplete {
		groupVersion, isDiscovery := strings.CutPrefix(gvr, "discovery:")
		switch {
		case !isDiscovery:
			c.incomplete[groupResource(gvr)] = struct{}{}
		case groupVersion == "*":
			return c, false
		default:
			// "v1" is the core group, "apps/v1" the apps group.
			group := ""
			if g, _, found := strings.Cut(groupVersion, "/"); found {
				group = g
			}
			c.groups[group] = struct{}{}
		}
	}
	return c, true
}

func (c collectedKinds) covers(labels map[string]string) bool {
	if labels[helpersv1.RbacResourceMetadataKey] == "true" {
		for _, gvr := range rbacGVRs {
			key := groupResource(gvr)
			if _, listed := c.listed[key]; listed && !c.listedInFull(key) {
				return false
			}
		}
		return true
	}
	gvr, err := k8sinterface.GetGroupVersionResource(labels[helpersv1.RelatedKindMetadataKey])
	if err != nil {
		return false
	}
	return c.listedInFull(labels[helpersv1.ApiGroupMetadataKey] + "/" + gvr.Resource)
}

func (c collectedKinds) listedInFull(key string) bool {
	if !c.listed[key] {
		return false
	}
	if _, ok := c.incomplete[key]; ok {
		return false
	}
	group, _, _ := strings.Cut(key, "/")
	_, ok := c.groups[group]
	return !ok
}

// groupResource turns <group>/<version>/<resource> into <group>/<resource>.
func groupResource(gvr string) string {
	group, _, resource := k8sinterface.StringToResourceGroup(gvr)
	return group + "/" + resource
}

// listUnrefreshedSummaries lists the summaries in all namespaces whose report
// timestamp is older than this report. A list response carries no controls, so
// the caller reads each candidate again before it decides.
func (a *APIServerStore) listUnrefreshedSummaries(ctx context.Context, pr *v2.PostureReport) ([]v1beta1.WorkloadConfigurationScanSummary, error) {
	var candidates []v1beta1.WorkloadConfigurationScanSummary
	opts := metav1.ListOptions{Limit: sweepListPageSize}
	for {
		list, err := a.StorageClient.WorkloadConfigurationScanSummaries("").List(ctx, opts)
		if err != nil {
			return nil, err
		}
		for i := range list.Items {
			if compareReportTimes(summaryReportTime(list.Items[i].Annotations), pr.ReportGenerationTime) == 1 {
				candidates = append(candidates, list.Items[i])
			}
		}
		if list.Continue == "" {
			return candidates, nil
		}
		opts.Continue = list.Continue
	}
}

// sweepScope is what one report can vouch for.
type sweepScope struct {
	reportTime time.Time
	excluded   []string
	collected  collectedKinds
	evaluated  map[string]struct{}
}

// inScope checks what a summary's metadata tells: the report did not write
// it, and its namespace and kind were scanned in full. A list response
// carries no controls, so controlsEvaluated is checked on the full object.
func (s sweepScope) inScope(meta metav1.ObjectMeta) bool {
	return compareReportTimes(summaryReportTime(meta.Annotations), s.reportTime) == 1 &&
		!slices.Contains(s.excluded, meta.Labels[helpersv1.RelatedNamespaceMetadataKey]) &&
		s.collected.covers(meta.Labels)
}

func (a *APIServerStore) deleteIfOrphaned(ctx context.Context, pr *v2.PostureReport, scope sweepScope, candidate *v1beta1.WorkloadConfigurationScanSummary) (bool, error) {
	summaries := a.StorageClient.WorkloadConfigurationScanSummaries(candidate.Namespace)
	summary, err := summaries.Get(ctx, candidate.Name, metav1.GetOptions{})
	if errors.IsNotFound(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	// Judge the full object again: a scan may have rewritten it since the list.
	if !scope.inScope(summary.ObjectMeta) || !controlsEvaluated(summary.Spec.Controls, scope.evaluated) {
		return false, nil
	}

	// The scan goes first: candidates are found through their summary, so a
	// scan left behind by a failed delete could never be found again.
	if deleted, err := a.deleteUnrefreshedScan(ctx, pr, summary.Namespace, summary.Name); !deleted || err != nil {
		return false, err
	}

	err = summaries.Delete(ctx, summary.Name, deleteUnchanged(summary.ObjectMeta))
	if errors.IsNotFound(err) || errors.IsConflict(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	logger.L().Debug("deleted orphaned posture record",
		helpers.String("namespace", summary.Namespace), helpers.String("name", summary.Name),
		helpers.String("wlid", summary.Annotations[helpersv1.WlidMetadataKey]))
	return true, nil
}

// deleteUnrefreshedScan deletes the WorkloadConfigurationScan of a summary
// unless a later scan rewrote it. It returns true when the summary can go too,
// which includes a scan that does not exist.
func (a *APIServerStore) deleteUnrefreshedScan(ctx context.Context, pr *v2.PostureReport, namespace, name string) (bool, error) {
	scans := a.StorageClient.WorkloadConfigurationScans(namespace)
	scan, err := scans.Get(ctx, name, metav1.GetOptions{})
	if errors.IsNotFound(err) {
		return true, nil
	}
	if err != nil {
		return false, fmt.Errorf("failed to get workload configuration scan: %w", err)
	}
	if compareReportTimes(workloadScanReportTime(scan), pr.ReportGenerationTime) != 1 {
		return false, nil
	}
	err = scans.Delete(ctx, name, deleteUnchanged(scan.ObjectMeta))
	switch {
	case errors.IsConflict(err):
		return false, nil
	case err != nil && !errors.IsNotFound(err):
		return false, fmt.Errorf("failed to delete workload configuration scan: %w", err)
	}
	return true, nil
}

// deleteUnchanged deletes an object only while it is the version that was read.
func deleteUnchanged(meta metav1.ObjectMeta) metav1.DeleteOptions {
	uid, resourceVersion := meta.UID, meta.ResourceVersion
	return metav1.DeleteOptions{
		Preconditions: &metav1.Preconditions{UID: &uid, ResourceVersion: &resourceVersion},
	}
}

// controlsEvaluated reports whether this scan evaluated every control of a
// record. A record without controls is left alone, because no control of this
// scan can say that its object is gone.
func controlsEvaluated(controls map[string]v1beta1.ScannedControlSummary, evaluated map[string]struct{}) bool {
	if len(controls) == 0 {
		return false
	}
	for id := range controls {
		if _, ok := evaluated[id]; !ok {
			return false
		}
	}
	return true
}
