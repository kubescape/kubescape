package printer

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"time"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/armoapi-go/identifiers"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling/printer"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
)

const (
	exceptionsOutputFile = "exceptions"
	exceptionPolicyType  = "postureExceptionPolicy"

	// emptyNamespacePattern pins a designator to a resource that recorded no
	// namespace, whether because it is cluster-scoped or because the manifest
	// omitted one. An absent namespace attribute is not equivalent: the
	// processor skips the axis entirely and the policy then covers every
	// namespace.
	emptyNamespacePattern = "^$"

	// namespaceKind is compared against the namespace axis by its own name, see
	// namespaceAttribute.
	namespaceKind = "Namespace"
)

type ExceptionsPrinter struct {
	writer *os.File
}

func NewExceptionsPrinter() *ExceptionsPrinter {
	return &ExceptionsPrinter{}
}

func (ep *ExceptionsPrinter) SetWriter(ctx context.Context, outputFile string) error {
	outputFile, explicitOutput := printer.ResolveOutputFile(printer.ExceptionsFormat, outputFile, exceptionsOutputFile)
	if explicitOutput {
		var err error
		ep.writer, err = printer.GetWriterNoFallback(outputFile)
		return err
	}
	ep.writer = printer.GetWriter(ctx, outputFile)
	return nil
}

func (ep *ExceptionsPrinter) Score(float32) {}

func (ep *ExceptionsPrinter) PrintNextSteps() {}

func (ep *ExceptionsPrinter) ActionPrint(ctx context.Context, opaSessionObj *cautils.OPASessionObj, _ []cautils.ImageScanData) error {
	if opaSessionObj == nil {
		return fmt.Errorf("failed to write exceptions: no data provided")
	}

	policies := buildExceptionPolicies(ctx, opaSessionObj)
	if len(policies) == 0 {
		logger.L().Ctx(ctx).Warning("no failed controls to write as exceptions")
	}

	encoded, err := json.MarshalIndent(exceptionDocuments(policies), "", "    ")
	if err != nil {
		logger.L().Ctx(ctx).Error("failed to encode exceptions", helpers.Error(err))
		return fmt.Errorf("failed to encode exceptions: %w", err)
	}
	encoded = append(encoded, '\n')

	if _, err := ep.writer.Write(encoded); err != nil {
		logger.L().Ctx(ctx).Error("failed to write exceptions", helpers.Error(err))
		return fmt.Errorf("failed to write exceptions: %w", err)
	}

	printer.LogOutputFile(ep.writer.Name())
	return nil
}

// buildExceptionPolicies turns the scan's failed controls into one exception
// policy per control, each listing the resources that failed it. Designators
// carry no cluster attribute so the generated file stays usable against any
// cluster the same workloads are deployed to.
//
// Control IDs are escaped for the same reason as the designator attributes: the
// processor regex-matches them, and a custom rule's ID carries whatever
// characters its file or directory was named with.
func buildExceptionPolicies(ctx context.Context, opaSessionObj *cautils.OPASessionObj) []armotypes.PostureExceptionPolicy {
	failures := collectFailures(ctx, opaSessionObj)
	if len(failures) == 0 {
		return []armotypes.PostureExceptionPolicy{}
	}

	creationTime := opaSessionObj.Report.ReportGenerationTime
	if creationTime.IsZero() {
		creationTime = time.Now().UTC()
	}

	controlIDs := make([]string, 0, len(failures))
	for controlID := range failures {
		controlIDs = append(controlIDs, controlID)
	}
	sort.Strings(controlIDs)

	policies := make([]armotypes.PostureExceptionPolicy, 0, len(controlIDs))
	for _, controlID := range controlIDs {
		policies = append(policies, armotypes.PostureExceptionPolicy{
			PortalBase:      armotypes.PortalBase{Name: "exclude-" + controlID},
			PolicyType:      exceptionPolicyType,
			CreationTime:    creationTime.UTC().Format(time.RFC3339),
			Actions:         []armotypes.PostureExceptionPolicyActions{armotypes.AlertOnly},
			Resources:       designators(failures[controlID]),
			PosturePolicies: []armotypes.PosturePolicy{{ControlID: regexp.QuoteMeta(controlID)}},
		})
	}
	return policies
}

// CloseWriter closes the exceptions output writer, returning any error from
// flushing or closing.
func (ep *ExceptionsPrinter) CloseWriter() error {
	if ep.writer != nil && ep.writer != os.Stdout {
		return ep.writer.Close()
	}
	return nil
}

// exceptionDocument is the serialised form of an exception policy. The armotypes
// structs carry portal-only fields without omitempty, and this file is meant to
// be edited by hand and fed back through --exceptions, so it is written in the
// same shape as the examples under examples/exceptions.
type exceptionDocument struct {
	Name            string                                    `json:"name"`
	PolicyType      string                                    `json:"policyType"`
	CreationTime    string                                    `json:"creationTime,omitempty"`
	Actions         []armotypes.PostureExceptionPolicyActions `json:"actions"`
	Resources       []identifiers.PortalDesignator            `json:"resources"`
	PosturePolicies []posturePolicyDocument                   `json:"posturePolicies"`
}

type posturePolicyDocument struct {
	ControlID string `json:"controlID"`
}

func exceptionDocuments(policies []armotypes.PostureExceptionPolicy) []exceptionDocument {
	documents := make([]exceptionDocument, 0, len(policies))
	for _, policy := range policies {
		posturePolicies := make([]posturePolicyDocument, 0, len(policy.PosturePolicies))
		for _, posturePolicy := range policy.PosturePolicies {
			posturePolicies = append(posturePolicies, posturePolicyDocument{ControlID: posturePolicy.ControlID})
		}
		documents = append(documents, exceptionDocument{
			Name:            policy.Name,
			PolicyType:      policy.PolicyType,
			CreationTime:    policy.CreationTime,
			Actions:         policy.Actions,
			Resources:       policy.Resources,
			PosturePolicies: posturePolicies,
		})
	}
	return documents
}

// resourceKey identifies one failed workload. Several resources can share a
// kind and name across namespaces, and a repository can declare the same object
// in more than one file, so the source path is part of the identity too.
type resourceKey struct {
	kind      string
	namespace string
	name      string
	path      string
}

// collectFailures maps each failed control to the resources that failed it.
func collectFailures(ctx context.Context, opaSessionObj *cautils.OPASessionObj) map[string]map[resourceKey]struct{} {
	failures := map[string]map[resourceKey]struct{}{}

	for resourceID, result := range opaSessionObj.ResourcesResult {
		resource, ok := opaSessionObj.AllResources[resourceID]
		if !ok || resource == nil {
			if hasFailedControl(result) {
				logger.L().Ctx(ctx).Warning("skipping failed resource with no scanned object; its findings are not in the baseline",
					helpers.String("resourceID", resourceID))
			}
			continue
		}

		key := resourceKey{
			kind:      resource.GetKind(),
			namespace: resource.GetNamespace(),
			name:      resource.GetName(),
			path:      sourcePath(resource),
		}
		if key.kind == "" || key.name == "" {
			if hasFailedControl(result) {
				logger.L().Ctx(ctx).Warning("skipping failed resource with no kind or name; its findings are not in the baseline",
					helpers.String("resourceID", resourceID))
			}
			continue
		}

		for i := range result.AssociatedControls {
			control := &result.AssociatedControls[i]
			if control.GetStatus(nil).Status() != apis.StatusFailed {
				continue
			}
			if _, ok := failures[control.ControlID]; !ok {
				failures[control.ControlID] = map[resourceKey]struct{}{}
			}
			failures[control.ControlID][key] = struct{}{}
		}
	}

	return failures
}

func hasFailedControl(result resourcesresults.Result) bool {
	for i := range result.AssociatedControls {
		if result.AssociatedControls[i].GetStatus(nil).Status() == apis.StatusFailed {
			return true
		}
	}
	return false
}

// sourcePath returns the manifest a locally scanned resource was read from.
// Cluster scans carry none, and the path axis is then left off entirely.
func sourcePath(resource workloadinterface.IMetadata) string {
	object := resource.GetObject()
	if object == nil {
		return ""
	}
	path, _ := object["sourcePath"].(string)
	return path
}

// designators renders one designator per resource. Values are escaped because
// the exception processor compares every attribute as an anchored regular
// expression: an unescaped name such as a CRD's widgets.example.com would also
// match widgetsXexampleYcom and silence findings on a resource this baseline
// never described.
// namespaceAttribute resolves the namespace axis of a designator. Every
// resource gets one: a manifest scanned without metadata.namespace still
// describes a specific object, and leaving the attribute off would widen the
// policy from that object to every namespace it could be deployed into.
//
// A Namespace object is the exception. The processor compares this axis against
// the object's own name rather than its metadata.namespace, so a Namespace has
// to be pinned by name or the policy is dead on arrival.
func namespaceAttribute(key resourceKey) string {
	if key.kind == namespaceKind {
		return regexp.QuoteMeta(key.name)
	}
	if key.namespace == "" {
		return emptyNamespacePattern
	}
	return regexp.QuoteMeta(key.namespace)
}

func designators(keys map[resourceKey]struct{}) []identifiers.PortalDesignator {
	ordered := make([]resourceKey, 0, len(keys))
	for key := range keys {
		ordered = append(ordered, key)
	}
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].kind != ordered[j].kind {
			return ordered[i].kind < ordered[j].kind
		}
		if ordered[i].namespace != ordered[j].namespace {
			return ordered[i].namespace < ordered[j].namespace
		}
		if ordered[i].name != ordered[j].name {
			return ordered[i].name < ordered[j].name
		}
		return ordered[i].path < ordered[j].path
	})

	result := make([]identifiers.PortalDesignator, 0, len(ordered))
	for _, key := range ordered {
		attributes := map[string]string{
			identifiers.AttributeKind: regexp.QuoteMeta(key.kind),
			identifiers.AttributeName: regexp.QuoteMeta(key.name),
		}
		attributes[identifiers.AttributeNamespace] = namespaceAttribute(key)
		// A repository can declare the same object in several files, a kustomize
		// base and its overlay being the common case. Without the source path
		// the policy covers every copy, so a later finding in one file is
		// suppressed by another file's baseline entry.
		if key.path != "" {
			attributes[identifiers.AttributePath] = regexp.QuoteMeta(key.path)
		}
		result = append(result, identifiers.PortalDesignator{
			DesignatorType: identifiers.DesignatorAttributes,
			Attributes:     attributes,
		})
	}
	return result
}
