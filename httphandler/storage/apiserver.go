package storage

import (
	"context"
	"fmt"

	"github.com/armosec/utils-k8s-go/wlid"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/k8s-interface/names"
	"golang.org/x/exp/maps"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/k8s-interface/workloadinterface"

	"github.com/kubescape/opa-utils/objectsenvelopes"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	v2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/kubescape/storage/pkg/generated/clientset/versioned"
	spdxv1beta1 "github.com/kubescape/storage/pkg/generated/clientset/versioned/typed/softwarecomposition/v1beta1"
	"go.opentelemetry.io/otel"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/util/retry"
)

var storageInstance *APIServerStore

type PostureRepository interface {
	GetWorkloadConfigurationScanResult(ctx context.Context, name, namespace string) (*v1beta1.WorkloadConfigurationScan, error)
	StoreWorkloadConfigurationScanResult(ctx context.Context, report *v2.PostureReport, result *resourcesresults.Result) (*v1beta1.WorkloadConfigurationScan, error)
	StoreWorkloadConfigurationScanResultSummary(ctx context.Context, workloadScan *v1beta1.WorkloadConfigurationScan) (*v1beta1.WorkloadConfigurationScanSummary, error)
}

// APIServerStore implements both PostureRepository with in-cluster storage (apiserver) to be used for production
type APIServerStore struct {
	StorageClient spdxv1beta1.SpdxV1beta1Interface
	clusterName   string
	namespace     string
}

var _ PostureRepository = (*APIServerStore)(nil)

func SetStorage(s *APIServerStore) {
	storageInstance = s
}

func GetStorage() *APIServerStore {
	return storageInstance
}

// NewAPIServerStorage initializes the APIServerStore struct
func NewAPIServerStorage(clusterName string, namespace string, config *rest.Config) (*APIServerStore, error) {
	// disable rate limiting
	config.QPS = 0
	config.RateLimiter = nil
	clientset, err := versioned.NewForConfig(config)
	if err != nil {
		return nil, err
	}
	return &APIServerStore{
		StorageClient: clientset.SpdxV1beta1(),
		clusterName:   clusterName,
		namespace:     namespace,
	}, nil
}

func (a *APIServerStore) StorePostureReportResults(ctx context.Context, pr *v2.PostureReport) error {
	for i := range pr.Results {
		detailedObj, err := a.StoreWorkloadConfigurationScanResult(ctx, pr, &pr.Results[i])
		if err != nil {
			return err
		}

		if _, err := a.StoreWorkloadConfigurationScanResultSummary(ctx, detailedObj); err != nil {
			return err
		}

	}
	return nil
}

func getControlsMapFromResult(ctx context.Context, result *resourcesresults.Result, controlSummaries reportsummary.ControlSummaries) map[string]v1beta1.ScannedControl {
	m := map[string]v1beta1.ScannedControl{}

	for i := range result.AssociatedControls {
		control := result.AssociatedControls[i]
		ctrlSummary := controlSummaries.GetControl(reportsummary.EControlCriteriaID, control.GetID())

		m[control.GetID()] = v1beta1.ScannedControl{
			ControlID: control.GetID(),
			Name:      control.GetName(),
			Severity:  parseControlSeverity(ctrlSummary),
			Status:    parseScannedControlStatus(&control),
			Rules:     parseScannedControlRules(&control),
		}

	}
	return m
}

func (a *APIServerStore) GetWorkloadConfigurationScanResult(ctx context.Context, name, namespace string) (*v1beta1.WorkloadConfigurationScan, error) {
	_, span := otel.Tracer("").Start(ctx, "APIServerStore.GetWorkloadConfigurationScanResult")
	defer span.End()
	if name == "" {
		logger.L().Debug("empty name provided, skipping workload scan result retrieval")
		return &v1beta1.WorkloadConfigurationScan{}, nil
	}
	manifest, err := a.StorageClient.WorkloadConfigurationScans(namespace).Get(context.Background(), name, metav1.GetOptions{})
	switch {
	case errors.IsNotFound(err):
		logger.L().Debug("workload configuration scan manifest not found in storage",
			helpers.String("name", name))
		return &v1beta1.WorkloadConfigurationScan{}, nil
	case err != nil:
		logger.L().Ctx(ctx).Warning("failed to get workload configuration scan manifest from apiserver", helpers.Error(err),
			helpers.String("name", name))
		return &v1beta1.WorkloadConfigurationScan{}, nil
	}

	logger.L().Debug("got workload configuration scan manifest from storage", helpers.String("name", name))
	return manifest, nil
}

func findResourceInReport(resourceID string, report *v2.PostureReport) (*reporthandling.Resource, error) {
	for i := range report.Resources {
		if report.Resources[i].ResourceID == resourceID {
			return &report.Resources[i], nil
		}
	}

	return nil, fmt.Errorf("resource %s not found in report", resourceID)
}

func (a *APIServerStore) getResourceNamespace(resource workloadinterface.IMetadata, relatedObjects []workloadinterface.IMetadata) string {
	if resource.GetNamespace() == "" || len(relatedObjects) > 0 {
		return a.namespace
	}

	return resource.GetNamespace()
}

func (a *APIServerStore) StoreWorkloadConfigurationScanResult(ctx context.Context, report *v2.PostureReport, result *resourcesresults.Result) (*v1beta1.WorkloadConfigurationScan, error) {
	resource, err := findResourceInReport(result.ResourceID, report)
	if err != nil {
		return nil, err
	}

	relatedObjects := getRelatedObjects(resource)
	name, err := GetWorkloadScanK8sResourceName(ctx, resource, relatedObjects)

	if err != nil {
		return nil, err
	}
	namespace := a.getResourceNamespace(resource, relatedObjects)
	labels, annotations, err := getManifestObjectLabelsAndAnnotations(a.clusterName, resource, relatedObjects)
	if err != nil {
		return nil, err
	}

	manifest := v1beta1.WorkloadConfigurationScan{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Annotations: annotations,
			Labels:      labels,
			Namespace:   namespace,
		},
		Spec: v1beta1.WorkloadConfigurationScanSpec{
			Controls:       getControlsMapFromResult(ctx, result, report.SummaryDetails.Controls),
			RelatedObjects: parseWorkloadScanRelatedObjectList(relatedObjects),
		},
	}

	// This is a workaround for the fact that the apiserver does not return already exist error on Create
	existing, err := a.StorageClient.WorkloadConfigurationScans(namespace).Get(context.Background(), manifest.Name, metav1.GetOptions{})
	if err == nil {
		logger.L().Debug("found existing WorkloadConfigurationScan manifest in storage - merging manifests", helpers.String("name", manifest.Name))
		manifest.Annotations = existing.Annotations
		manifest.Labels = existing.Labels
		manifest.Spec = mergeWorkloadConfigurationScanSpec(existing.Spec, manifest.Spec)
	}

	_, err = a.StorageClient.WorkloadConfigurationScans(namespace).Create(context.Background(), &manifest, metav1.CreateOptions{})
	switch {
	case errors.IsAlreadyExists(err):
		retryErr := retry.RetryOnConflict(retry.DefaultRetry, func() error {
			// retrieve the latest version before attempting update
			// RetryOnConflict uses exponential backoff to avoid exhausting the apiserver
			result, getErr := a.StorageClient.WorkloadConfigurationScans(namespace).Get(context.Background(), manifest.Name, metav1.GetOptions{})
			if getErr != nil {
				return getErr
			}
			// update the workload configuration scan manifest
			result.Annotations = manifest.Annotations
			result.Labels = manifest.Labels
			result.Spec = mergeWorkloadConfigurationScanSpec(result.Spec, manifest.Spec)
			manifest = *result
			// try to send the updated workload configuration scan manifest
			_, updateErr := a.StorageClient.WorkloadConfigurationScans(namespace).Update(context.Background(), result, metav1.UpdateOptions{})
			return updateErr
		})
		if retryErr != nil {
			logger.L().Ctx(ctx).Warning("failed to update WorkloadConfigurationScan manifest in storage", helpers.Error(err),
				helpers.String("name", manifest.Name))
		} else {
			logger.L().Debug("updated WorkloadConfigurationScan manifest in storage", helpers.String("name", manifest.Name))
		}
	case err != nil:
		logger.L().Ctx(ctx).Warning("failed to store WorkloadConfigurationScan manifest in storage", helpers.Error(err), helpers.String("name", manifest.Name))
		return nil, err
	default:
		logger.L().Debug("stored WorkloadConfigurationScan manifest in storage", helpers.String("name", manifest.Name))
	}
	return &manifest, nil
}

func mergeWorkloadConfigurationScanSpec(existingSpec v1beta1.WorkloadConfigurationScanSpec, newSpec v1beta1.WorkloadConfigurationScanSpec) v1beta1.WorkloadConfigurationScanSpec {
	for ctrlID := range newSpec.Controls {
		newCtrl := newSpec.Controls[ctrlID]
		_, found := existingSpec.Controls[ctrlID]
		if !found {
			existingSpec.Controls[ctrlID] = newCtrl
			continue
		}

		// TODOs:
		// 1. Decide what to do with existing controls (compare statuses, what is the merge strategy)
		// 2. Do we need to merge the rules?
		// 3. Do we need to remove non-existing controls?
		existingSpec.Controls[ctrlID] = newCtrl
	}

	existingSpec.RelatedObjects = newSpec.RelatedObjects
	return existingSpec
}

func mergeWorkloadConfigurationScanSummarySpec(existingSpec v1beta1.WorkloadConfigurationScanSummarySpec, newSpec v1beta1.WorkloadConfigurationScanSummarySpec) v1beta1.WorkloadConfigurationScanSummarySpec {
	for ctrlID := range newSpec.Controls {
		newCtrl := newSpec.Controls[ctrlID]
		_, found := existingSpec.Controls[ctrlID]
		if !found {
			existingSpec.Controls[ctrlID] = newCtrl
			continue
		}

		// TODOs:
		// 1. Decide what to do with existing controls (compare statuses, what is the merge strategy)
		// 2. Do we need to merge the rules?
		// 3. Do we need to remove non-existing controls?
		existingSpec.Controls[ctrlID] = newCtrl
	}

	existingSpec.Severities = calculateSeveritiesSummaryFromControls(existingSpec.Controls)
	return existingSpec
}

func (a *APIServerStore) StoreWorkloadConfigurationScanResultSummary(ctx context.Context, workloadScan *v1beta1.WorkloadConfigurationScan) (*v1beta1.WorkloadConfigurationScanSummary, error) {
	_, span := otel.Tracer("").Start(ctx, "APIServerStore.StoreWorkloadConfigurationScanResultSummary")
	defer span.End()

	controlsSummary := getControlsSummaryMapFromScannedControlMap(ctx, workloadScan.Spec.Controls)
	severities := calculateSeveritiesSummaryFromControls(controlsSummary)
	namespace := workloadScan.GetNamespace()
	manifest := v1beta1.WorkloadConfigurationScanSummary{
		ObjectMeta: metav1.ObjectMeta{
			Name:        workloadScan.Name,
			Namespace:   namespace,
			Annotations: workloadScan.Annotations,
			Labels:      workloadScan.Labels,
		},
		Spec: v1beta1.WorkloadConfigurationScanSummarySpec{
			Severities: severities,
			Controls:   controlsSummary,
		},
	}

	// This is a workaround for the fact that the apiserver does not return already exist error on Create
	existing, err := a.StorageClient.WorkloadConfigurationScanSummaries(namespace).Get(context.Background(), manifest.Name, metav1.GetOptions{})
	if err == nil {
		logger.L().Debug("found existing WorkloadConfigurationScanSummary manifest in storage - merging manifests", helpers.String("name", manifest.Name))
		manifest.Annotations = existing.Annotations
		manifest.Labels = existing.Labels
		manifest.Spec = mergeWorkloadConfigurationScanSummarySpec(existing.Spec, manifest.Spec)
	}

	_, err = a.StorageClient.WorkloadConfigurationScanSummaries(namespace).Create(context.Background(), &manifest, metav1.CreateOptions{})
	switch {
	case errors.IsAlreadyExists(err):
		retryErr := retry.RetryOnConflict(retry.DefaultRetry, func() error {
			// retrieve the latest version before attempting update
			// RetryOnConflict uses exponential backoff to avoid exhausting the apiserver
			result, getErr := a.StorageClient.WorkloadConfigurationScanSummaries(namespace).Get(context.Background(), manifest.Name, metav1.GetOptions{})
			if getErr != nil {
				return getErr
			}
			// update the manifest
			result.Annotations = manifest.Annotations
			result.Labels = manifest.Labels
			result.Spec = mergeWorkloadConfigurationScanSummarySpec(result.Spec, manifest.Spec)
			manifest = *result
			// try to send the updated manifest
			_, updateErr := a.StorageClient.WorkloadConfigurationScanSummaries(namespace).Update(context.Background(), result, metav1.UpdateOptions{})
			return updateErr
		})
		if retryErr != nil {
			logger.L().Ctx(ctx).Warning("failed to update WorkloadConfigurationScanSummary manifest in storage", helpers.Error(err),
				helpers.String("name", manifest.Name))
		} else {
			logger.L().Debug("updated WorkloadConfigurationScanSummary manifest in storage",
				helpers.String("name", manifest.Name))
		}
	case err != nil:
		logger.L().Ctx(ctx).Warning("failed to store WorkloadConfigurationScanSummary manifest in storage", helpers.Error(err),
			helpers.String("name", manifest.Name))
		return nil, err
	default:
		logger.L().Debug("stored WorkloadConfigurationScanSummary manifest in storage",
			helpers.String("name", manifest.Name))
	}
	return &manifest, nil
}

func updateLabelsAndAnnotationsMapFromRelatedObjects(clusterName string, labels map[string]string, annotations map[string]string, relatedObjects []workloadinterface.IMetadata) error {
	labels[helpersv1.RbacResourceMetadataKey] = "true"

	for i := range relatedObjects {
		relatedObject := relatedObjects[i]
		switch relatedObject.GetKind() {
		case "Role":
			labels[helpersv1.RoleNameMetadataKey] = relatedObject.GetName()
			labels[helpersv1.RoleNamespaceMetadataKey] = relatedObject.GetNamespace()
		case "RoleBinding":
			labels[helpersv1.RoleBindingNameMetadataKey] = relatedObject.GetName()
			labels[helpersv1.RoleBindingNamespaceMetadataKey] = relatedObject.GetNamespace()
			annotations[helpersv1.WlidMetadataKey] = wlid.GetK8sWLID(clusterName, relatedObject.GetNamespace(), relatedObject.GetKind(), relatedObject.GetName())
		case "ClusterRole":
			labels[helpersv1.ClusterRoleNameMetadataKey] = relatedObject.GetName()
		case "ClusterRoleBinding":
			labels[helpersv1.ClusterRoleBindingNameMetadataKey] = relatedObject.GetName()
			annotations[helpersv1.WlidMetadataKey] = wlid.GetK8sWLID(clusterName, "", relatedObject.GetKind(), relatedObject.GetName())
		default:
			return fmt.Errorf("unknown related object kind %s", relatedObject.GetKind())
		}
	}
	return nil
}

func getManifestObjectLabelsAndAnnotations(clusterName string, resource workloadinterface.IMetadata, relatedObjects []workloadinterface.IMetadata) (map[string]string, map[string]string, error) {
	annotations := map[string]string{
		helpersv1.WlidMetadataKey: wlid.GetK8sWLID(clusterName, resource.GetNamespace(), resource.GetKind(), resource.GetName()),
	}
	labels := make(map[string]string)
	labels[helpersv1.ApiGroupMetadataKey], labels[helpersv1.ApiVersionMetadataKey] = k8sinterface.SplitApiVersion(resource.GetApiVersion())
	labels[helpersv1.KindMetadataKey] = resource.GetKind()
	labels[helpersv1.NameMetadataKey] = resource.GetName()
	if k8sinterface.IsResourceInNamespaceScope(resource.GetKind()) {
		labels[helpersv1.NamespaceMetadataKey] = resource.GetNamespace()
	}

	if len(relatedObjects) > 0 {
		if err := updateLabelsAndAnnotationsMapFromRelatedObjects(clusterName, labels, annotations, relatedObjects); err != nil {
			return nil, nil, err
		}
	}

	names.SanitizeLabelValues(labels)

	return labels, annotations, nil
}

// getRelatedObjects returns a list of related objects for the given resource
// This is only relevant for RegoResponseVector objects (which are a triplet of <Subject, Role, RoleBinding>
// For other objects, an empty list is returned
func getRelatedObjects(resource *reporthandling.Resource) []workloadinterface.IMetadata {
	obj := resource.GetObject()
	if !objectsenvelopes.IsTypeRegoResponseVector(obj) {
		return []workloadinterface.IMetadata{}
	}
	return objectsenvelopes.NewRegoResponseVectorObject(obj).GetRelatedObjects()
}

func getRoleAndRoleBindingFromRelatedObjects(relatedObjects []workloadinterface.IMetadata) (role workloadinterface.IMetadata, roleBinding workloadinterface.IMetadata, err error) {
	if len(relatedObjects) != 2 {
		return nil, nil, fmt.Errorf("expected 2 related objects, got %d", len(relatedObjects))
	}

	for i := range relatedObjects {
		switch relatedObjects[i].GetKind() {
		case "Role", "ClusterRole":
			role = relatedObjects[i]
		case "RoleBinding", "ClusterRoleBinding":
			roleBinding = relatedObjects[i]
		default:
			return nil, nil, fmt.Errorf("unknown related object kind %s", relatedObjects[i].GetKind())
		}
	}
	return role, roleBinding, nil
}

func GetWorkloadScanK8sResourceName(ctx context.Context, resource workloadinterface.IMetadata, relatedObjects []workloadinterface.IMetadata) (string, error) {
	if len(relatedObjects) == 0 {
		return names.ResourceToSlug(resource)
	}

	role, roleBinding, err := getRoleAndRoleBindingFromRelatedObjects(relatedObjects)
	if err != nil {
		return "", err
	}

	return names.RoleBindingResourceToSlug(resource, role, roleBinding)
}

func calculateSeveritiesSummaryFromControls(controls map[string]v1beta1.ScannedControlSummary) v1beta1.WorkloadConfigurationScanSeveritiesSummary {
	critical := 0
	high := 0
	medium := 0
	low := 0
	unknown := 0

	for _, control := range controls {
		if apis.ScanningStatus(control.Status.Status) != apis.StatusFailed {
			continue
		}

		switch apis.ControlSeverityToInt(control.Severity.ScoreFactor) {
		case apis.SeverityCritical:
			critical += 1
		case apis.SeverityHigh:
			high += 1
		case apis.SeverityMedium:
			medium += 1
		case apis.SeverityLow:
			low += 1
		case apis.SeverityUnknown:
			unknown += 1
		}

	}

	return v1beta1.WorkloadConfigurationScanSeveritiesSummary{
		Critical: critical,
		High:     high,
		Medium:   medium,
		Low:      low,
		Unknown:  unknown,
	}
}

func getControlsSummaryMapFromScannedControlMap(ctx context.Context, scannedControls map[string]v1beta1.ScannedControl) map[string]v1beta1.ScannedControlSummary {
	m := map[string]v1beta1.ScannedControlSummary{}
	for id, control := range scannedControls {
		m[id] = v1beta1.ScannedControlSummary{
			ControlID: id,
			Severity:  control.Severity,
			Status:    control.Status,
		}
	}
	return m
}

func parseControlSeverity(controlSummary reportsummary.IControlSummary) v1beta1.ControlSeverity {
	scoreFactor := controlSummary.GetScoreFactor()
	severity := apis.ControlSeverityToString(scoreFactor)

	return v1beta1.ControlSeverity{
		Severity:    severity,
		ScoreFactor: scoreFactor,
	}
}

func parseScannedControlRules(control *resourcesresults.ResourceAssociatedControl) []v1beta1.ScannedControlRule {
	rules := make([]v1beta1.ScannedControlRule, len(control.ResourceAssociatedRules))
	for i, rule := range control.ResourceAssociatedRules {
		paths := make([]v1beta1.RulePath, len(rule.Paths))
		for j, path := range rule.Paths {
			paths[j] = v1beta1.RulePath{
				FailedPath:   path.FailedPath,
				FixPath:      path.FixPath.Path,
				FixPathValue: path.FixPath.Value,
				FixCommand:   path.FixCommand,
			}
		}
		appliedIgnoreRules := make([]string, len(rule.Exception))
		for j, exception := range rule.Exception {
			appliedIgnoreRules[j] = exception.GetName()
		}

		controlConfigurations := make(map[string][]string)
		maps.Copy(controlConfigurations, rule.ControlConfigurations)

		relatedResourceIds := []string{}
		copy(relatedResourceIds, rule.RelatedResourcesIDs)
		rules[i] = v1beta1.ScannedControlRule{
			Name: rule.GetName(),
			Status: v1beta1.RuleStatus{
				Status:    string(rule.GetStatus(nil).Status()),
				SubStatus: string(rule.GetStatus(nil).GetSubStatus()),
			},
			ControlConfigurations: controlConfigurations,
			Paths:                 paths,
			AppliedIgnoreRules:    appliedIgnoreRules,
			RelatedResourcesIDs:   relatedResourceIds,
		}
	}
	return rules
}

func parseScannedControlStatus(control *resourcesresults.ResourceAssociatedControl) v1beta1.ScannedControlStatus {
	return v1beta1.ScannedControlStatus{
		Status:    string(control.GetStatus(nil).Status()),
		SubStatus: string(control.GetSubStatus()),
		Info:      control.GetStatus(nil).Info(),
	}
}

func parseWorkloadScanRelatedObjectList(relatedObjects []workloadinterface.IMetadata) []v1beta1.WorkloadScanRelatedObject {
	r := make([]v1beta1.WorkloadScanRelatedObject, len(relatedObjects))
	for i := range relatedObjects {
		group, version := k8sinterface.SplitApiVersion(relatedObjects[i].GetApiVersion())
		r[i] = v1beta1.WorkloadScanRelatedObject{
			Namespace:  relatedObjects[i].GetNamespace(),
			APIGroup:   group,
			APIVersion: version,
			Kind:       relatedObjects[i].GetKind(),
			Name:       relatedObjects[i].GetName(),
		}
	}
	return r
}
