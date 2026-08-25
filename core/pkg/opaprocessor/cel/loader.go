package cel

import (
	"bytes"
	"embed"
	"errors"
	"fmt"
	"io"
	"sync"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8syaml "k8s.io/apimachinery/pkg/util/yaml"
	"sigs.k8s.io/yaml"
)

// vapdataFS bakes the vendored cel-admission-library bundle (see vapdata/README.md)
// into the binary. Embedding keeps the VAP YAML as the source of truth (per issue
// #2001) and pinned to the vendored release, with no runtime file-path lookups or
// network fetch at scan time.
//
//go:embed vapdata
var vapdataFS embed.FS

const (
	// vapdataDir is the embedded directory and, for the sanity tests, the on-disk
	// directory name (they run from the package dir).
	vapdataDir = "vapdata"
	// vapBundleFile holds the ValidatingAdmissionPolicy documents, one per `---`.
	vapBundleFile = "kubescape-validating-admission-policies.yaml"
	// controlConfigFile holds the ControlConfiguration a policy's paramKind
	// resolves against (issue #2001: params come from this file in the bundle).
	controlConfigFile = "basic-control-configuration.yaml"

	// controlIDLabel is the metadata label the bundle tags each control's policy
	// with (e.g. C-0017). Cluster-scoped helper policies carry no such label.
	controlIDLabel = "controlId"

	vapKind       = "ValidatingAdmissionPolicy"
	vapAPIVersion = "admissionregistration.k8s.io/v1"
)

// VAP is one ValidatingAdmissionPolicy from the bundle, reduced to what the
// evaluator consumes: the variables and validations already flattened into the
// evaluator's structs, plus the paramKind so resolveParams knows whether to bind
// params. The full YAML is parsed as a real ValidatingAdmissionPolicy first, so
// we keep the structure rather than a flattened string.
type VAP struct {
	ControlID   string
	PolicyName  string
	Variables   []Variable
	Validations []Validation

	// matchConditions gates whether a policy runs at all: at admission a policy
	// whose matchConditions evaluate to false is skipped and none of its
	// validations run. The evaluator honors the gate offline the same way (see
	// matchConditionsHold), so a gated policy is scanned rather than refused.
	matchConditions []MatchCondition

	// paramKind mirrors spec.paramKind; nil when the policy declares no params.
	paramKind *admissionregistrationv1.ParamKind

	// matchConstraints mirrors spec.matchConstraints: the GVKs the policy
	// applies to. Offline we use it to scope evaluation (see appliesTo), because
	// the validations self-guard by object.kind and evaluate to true for a
	// non-matching kind, which the scan would otherwise record as a pass live
	// admission never made (the object would not be matched at all).
	matchConstraints *admissionregistrationv1.MatchResources

	// failurePolicy mirrors spec.failurePolicy: how an evaluation error is
	// treated. The apiserver defaults an omitted policy to Fail, so newVAP
	// stores the resolved value (Fail when nil) rather than the raw pointer.
	failurePolicy admissionregistrationv1.FailurePolicyType
}

// failOnError reports whether an evaluation error denies the request. Only an
// explicit failurePolicy: Ignore changes that; every policy in the embedded
// bundle defaults to Fail.
func (v *VAP) failOnError() bool {
	return v.failurePolicy != admissionregistrationv1.Ignore
}

// requireSupported reports whether the offline engine can honor this policy with
// scan/admission parity. A refusal maps to the same errored/skipped status a
// Rego eval error takes, never a silent pass or a false violation. Removing a
// guard here is the seam for when the evaluator learns to honor that input —
// matchConditions came off this list once the evaluator could evaluate the gate
// (see matchConditionsHold).
//
// A namespaceSelector is refused for a subtler reason. Its input is the
// NAMESPACE's labels, and the scan only has those when some control's match
// happened to collect Namespaces (the same best-effort behind the
// namespaceObject binding, see the scanner's celNamespaceObjectFor). Evaluating
// it against an absent namespace would silently exempt objects admission
// matches, or match objects admission exempts, depending on the selector's
// direction — both are silent parity breaks, where refusal is a loud skip. So
// it stays refused not because the input never exists, but because it is not
// GUARANTEED to exist; the seam for honoring it is guaranteeing Namespace
// collection whenever a loaded policy needs it.
//
// A paramKind is refused for the same reason. Live, a binding's ParamRef points
// the policy at real objects of that kind, so a policy taking anything other
// than the ControlConfiguration the bundle ships has no offline params at all.
// Evaluating it anyway reads params.* off the wrong object, and every such read
// is a verdict admission never made. The seam for honoring one is resolving a
// ParamRef against objects the scan collected.
//
// The other matchConstraints narrowings do not need refusing, because their
// inputs are on the scanned object itself and appliesTo evaluates them:
// objectSelector (the object's own labels) and a resource rule's operations
// and resourceNames (the object's own name).
func (v *VAP) requireSupported() error {
	if err := v.requireNamespaceSelectorSupported(); err != nil {
		return err
	}
	if err := v.requireParamKindSupported(); err != nil {
		return err
	}
	return nil
}

func (v *VAP) requireNamespaceSelectorSupported() error {
	if v.matchConstraints != nil && selectorNarrows(v.matchConstraints.NamespaceSelector) {
		return fmt.Errorf("control %q scopes matchConstraints with a namespaceSelector, whose input (namespace labels) the scan cannot guarantee to have; refusing it to preserve scan/admission parity", v.ControlID)
	}
	return nil
}

func (v *VAP) requireParamKindSupported() error {
	if v.paramKind == nil {
		return nil
	}
	shipped, err := controlConfigParamKind()
	if err != nil {
		return err
	}
	if *v.paramKind != *shipped {
		return fmt.Errorf("control %q takes params of kind %s %s, which the scan has no binding to resolve (only the bundled %s %s is available); refusing it to preserve scan/admission parity", v.ControlID, v.paramKind.APIVersion, v.paramKind.Kind, shipped.APIVersion, shipped.Kind)
	}
	return nil
}

// selectorNarrows reports whether a label selector actually narrows anything.
// Both nil and the empty selector match every object (the empty selector is
// what the apiserver defaults an omitted one to), so only a selector carrying
// requirements makes the policy one the offline engine cannot honor.
func selectorNarrows(s *metav1.LabelSelector) bool {
	return s != nil && (len(s.MatchLabels) > 0 || len(s.MatchExpressions) > 0)
}

// vapCatalog is everything indexed out of the embedded bundle. It is built once
// and reused: parsing every document on each lookup would be wasteful, and the
// bundle never changes at runtime.
type vapCatalog struct {
	// byControl maps the controlId label -> policy, for the scan path.
	byControl map[string]*VAP
	// dupControls poisons controls claimed by more than one policy: neither
	// copy silently wins, and only that control is refused (the rest of the
	// bundle keeps working).
	dupControls map[string]struct{}
	// byName maps metadata.name -> policy. Unlike byControl it covers every
	// policy in the bundle, including the cluster-scoped helpers that carry no
	// controlId, so name-keyed callers (cmd/vap --policy) can look them up.
	byName map[string]*VAP
	// dupNames poisons names used by more than one policy, same scheme as
	// dupControls.
	dupNames map[string]struct{}
}

// vapCatalogErr is reserved for whole-bundle failures (the embed cannot be read
// or decoded) — the engine genuinely cannot function then. A per-policy problem
// like a duplicate never lands here: it poisons only its own key (see the dup
// sets on vapCatalog) so one bad policy cannot take the whole engine offline.
var (
	vapCatalogOnce sync.Once
	vapCatalogVal  *vapCatalog
	vapCatalogErr  error
)

// getVAPCatalog reads the embedded bundle once and hands the bytes to
// parseVAPBundle. Splitting the two keeps the parsing logic testable with
// in-memory bundles.
func getVAPCatalog() (*vapCatalog, error) {
	vapCatalogOnce.Do(func() {
		data, err := vapdataFS.ReadFile(vapdataDir + "/" + vapBundleFile)
		if err != nil {
			vapCatalogErr = fmt.Errorf("read embedded VAP bundle: %w", err)
			return
		}
		vapCatalogVal, vapCatalogErr = parseVAPBundle(data)
	})
	return vapCatalogVal, vapCatalogErr
}

// lookupVAP resolves a control ID to its policy without the requireSupported
// gate. It fails when the control is absent from the embedded bundle rather
// than silently returning nothing, so a caller cannot quietly skip a control it
// thinks it covers. Callers that evaluate the policy offline go through loadVAP
// instead; this seam exists for metadata lookups (see catalog.go) where a
// gated policy is still a valid answer.
func lookupVAP(controlID string) (*VAP, error) {
	catalog, err := getVAPCatalog()
	if err != nil {
		return nil, err
	}
	if _, dup := catalog.dupControls[controlID]; dup {
		return nil, fmt.Errorf("control %q is defined by more than one policy in the VAP bundle; refusing it rather than pick one", controlID)
	}
	vap, ok := catalog.byControl[controlID]
	if !ok {
		return nil, fmt.Errorf("no %s for control %q in embedded bundle", vapKind, controlID)
	}
	return vap, nil
}

// loadVAP returns the policy for a control ID (threaded in from processControl,
// never read off a rule), refusing policies the offline engine cannot evaluate
// with scan/admission parity (see requireSupported).
func loadVAP(controlID string) (*VAP, error) {
	vap, err := lookupVAP(controlID)
	if err != nil {
		return nil, err
	}
	if err := vap.requireSupported(); err != nil {
		return nil, err
	}
	return vap, nil
}

// LoadVAP is the exported entry point for callers that need the VAP to resolve
// a per-binding paramRef. It does not refuse a VAP merely because its paramKind
// is not the bundled one: a binding's paramRef may point to that kind in the
// scanned input. It still refuses namespaceSelector-narrowed policies.
func LoadVAP(controlID string) (*VAP, error) {
	vap, err := lookupVAP(controlID)
	if err != nil {
		return nil, err
	}
	if err := vap.requireNamespaceSelectorSupported(); err != nil {
		return nil, err
	}
	return vap, nil
}

// ErrParamNotFound signals that a binding's paramRef points to an object that
// is not present in the scanned input. The caller applies the binding's
// parameterNotFoundAction: Allow means the object is admitted, Deny/empty means
// the policy cannot produce a verdict and the rule is skipped.
var ErrParamNotFound = errors.New("param object not found")

// parseVAPBundle turns a multi-document bundle into a vapCatalog.
//
// It consumes only v1 ValidatingAdmissionPolicy documents and skips everything
// else. The bundle is a mixed stream synced from cel-admission-library, which
// also ships ValidatingAdmissionPolicyBinding (and blank) documents; failing the
// whole catalog over one document we do not consume would take the entire engine
// down on a routine `make sync-vap`, so a foreign kind is skipped, not fatal.
// Policies with no controlId label (cluster-scoped helper policies) land only in
// byName: they are not addressable by control and the scan never asks for them,
// but name-keyed callers still need them.
//
// A duplicate key (controlId or name) poisons only that key: two policies
// fighting over one control or name is a real bundle bug, so neither silently
// wins — the key is dropped from its index and recorded in the matching dup set,
// and lookups refuse it. The rest of the bundle still indexes, so one bad policy
// cannot take the whole engine offline. Only an unreadable/undecodable bundle is
// a whole-bundle error.
func parseVAPBundle(data []byte) (*vapCatalog, error) {
	catalog := &vapCatalog{
		byControl:   make(map[string]*VAP),
		dupControls: make(map[string]struct{}),
		byName:      make(map[string]*VAP),
		dupNames:    make(map[string]struct{}),
	}
	decoder := k8syaml.NewYAMLOrJSONDecoder(bytes.NewReader(data), 4096)
	for {
		var policy admissionregistrationv1.ValidatingAdmissionPolicy
		if err := decoder.Decode(&policy); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, fmt.Errorf("decode VAP bundle: %w", err)
		}

		if policy.Kind != vapKind || policy.APIVersion != vapAPIVersion {
			continue
		}

		vap := newVAP(&policy)
		indexUnique(catalog.byName, catalog.dupNames, vap.PolicyName, vap)
		indexUnique(catalog.byControl, catalog.dupControls, vap.ControlID, vap)
	}

	return catalog, nil
}

// indexUnique adds one policy under one key, enforcing the duplicate-poisoning
// scheme: the first occurrence indexes, a second drops the key from the index
// and marks it duplicated, and further occurrences stay poisoned. An empty key
// (a helper policy with no controlId) is simply not indexed.
func indexUnique(index map[string]*VAP, duplicates map[string]struct{}, key string, vap *VAP) {
	if key == "" {
		return
	}
	if _, poisoned := duplicates[key]; poisoned {
		return
	}
	if _, seen := index[key]; seen {
		duplicates[key] = struct{}{}
		delete(index, key)
		return
	}
	index[key] = vap
}

// newVAP flattens a parsed policy into the evaluator's structs. The message and
// messageExpression travel with each validation so the evaluator can resolve the
// violation message the same way the apiserver does. matchConditions are carried
// so the evaluator can honor the gate before running any validation.
//
// spec.matchConstraints is kept so the scan can scope evaluation to the kinds
// the policy actually applies to (see appliesTo); without it a non-matching
// object slips through the validations' self-guards as a pass. spec.failurePolicy
// is resolved here (the apiserver defaults an omitted policy to Fail) so the
// evaluator can report a validation whose expression errored as a deny, the
// parity-safe direction that matches admission.
func newVAP(policy *admissionregistrationv1.ValidatingAdmissionPolicy) *VAP {
	failurePolicy := admissionregistrationv1.Fail
	if policy.Spec.FailurePolicy != nil {
		failurePolicy = *policy.Spec.FailurePolicy
	}

	vap := &VAP{
		ControlID:        policy.Labels[controlIDLabel],
		PolicyName:       policy.Name,
		paramKind:        policy.Spec.ParamKind,
		matchConstraints: policy.Spec.MatchConstraints,
		failurePolicy:    failurePolicy,
	}
	for _, c := range policy.Spec.MatchConditions {
		vap.matchConditions = append(vap.matchConditions, MatchCondition{Name: c.Name, Expression: c.Expression})
	}
	for _, v := range policy.Spec.Variables {
		vap.Variables = append(vap.Variables, Variable{Name: v.Name, Expression: v.Expression})
	}
	for _, v := range policy.Spec.Validations {
		vap.Validations = append(vap.Validations, Validation{
			Expression:        v.Expression,
			Message:           v.Message,
			MessageExpression: v.MessageExpression,
		})
	}
	return vap
}

// ResolveParamObject returns the value bound to the evaluator's "params"
// variable for one binding's paramRef. A policy with no paramKind gets nil. A
// binding with no paramRef falls back to the bundled ControlConfiguration. A
// binding that names a specific param object is resolved from the scanned input
// via findParam. If the object is not found, ErrParamNotFound is returned so
// the caller can honor parameterNotFoundAction.
func ResolveParamObject(vap *VAP, paramRef *admissionregistrationv1.ParamRef, resourceNamespace string, findParam func(apiVersion, kind, namespace, name string) (map[string]any, bool)) (any, error) {
	if vap.paramKind == nil {
		return nil, nil
	}
	if paramRef == nil || paramRef.Name == "" {
		return resolveParams(vap)
	}
	for _, ns := range paramLookupNamespaces(paramRef, resourceNamespace) {
		if obj, ok := findParam(vap.paramKind.APIVersion, vap.paramKind.Kind, ns, paramRef.Name); ok {
			return obj, nil
		}
	}
	return nil, ErrParamNotFound
}

// paramLookupNamespaces returns the namespaces to look the param object up in,
// in order. An explicit namespace on the ref is the only candidate; without one
// the paramKind's scope decides where the object lives and offline there is no
// discovery to read that scope from, so both candidates are tried: the scanned
// resource's namespace for a namespaced kind, then the empty namespace the index
// keys a cluster-scoped one by. A kind is registered at exactly one scope, so the
// order cannot pick the wrong object. Trying only the resource's namespace missed
// the bundled ControlConfiguration (scope: Cluster) for every namespaced resource.
func paramLookupNamespaces(paramRef *admissionregistrationv1.ParamRef, resourceNamespace string) []string {
	if paramRef.Namespace != "" {
		return []string{paramRef.Namespace}
	}
	if resourceNamespace == "" {
		return []string{""}
	}
	return []string{resourceNamespace, ""}
}

// resolveParams returns the value bound to the evaluator's "params" variable. A
// policy with no paramKind gets nil (matching a live binding with no ParamRef).
// Otherwise the whole ControlConfiguration is returned so expressions can reach
// params.settings.<field>, exactly what a live ParamRef would supply.
//
// A paramKind the shipped file does not answer is an error rather than the
// config: binding the wrong object would answer the policy's params.* reads
// with another kind's fields. loadVAP refuses such a policy before we get here
// (see requireSupported), so this is the invariant kept where params are bound.
//
// The returned map is shared across calls (see controlConfig) and is treated as
// read-only: the evaluator only binds it into a CEL activation, which never
// mutates it.
func resolveParams(vap *VAP) (any, error) {
	if vap.paramKind == nil {
		return nil, nil
	}
	shipped, err := controlConfigParamKind()
	if err != nil {
		return nil, err
	}
	if *vap.paramKind != *shipped {
		return nil, fmt.Errorf("control %q takes params of kind %s %s, which the bundled %s %s cannot supply", vap.ControlID, vap.paramKind.APIVersion, vap.paramKind.Kind, shipped.APIVersion, shipped.Kind)
	}
	return controlConfig()
}

// controlConfigParamKind is the paramKind the embedded params file answers,
// read off the file's own apiVersion and kind so a `make sync-vap` that bumps
// the ControlConfiguration version carries the check with it.
func controlConfigParamKind() (*admissionregistrationv1.ParamKind, error) {
	config, err := controlConfig()
	if err != nil {
		return nil, err
	}
	apiVersion, _ := config["apiVersion"].(string)
	kind, _ := config["kind"].(string)
	if apiVersion == "" || kind == "" {
		return nil, fmt.Errorf("embedded control configuration %q declares no apiVersion/kind, so no policy's paramKind can be matched against it", controlConfigFile)
	}
	return &admissionregistrationv1.ParamKind{APIVersion: apiVersion, Kind: kind}, nil
}

// controlConfig parses the embedded ControlConfiguration once and caches it. It
// is one shared file with identical content for every params-bearing control, so
// re-reading and re-parsing it per evaluation would be wasted work.
var (
	controlConfigOnce sync.Once
	controlConfigVal  map[string]any
	controlConfigErr  error
)

func controlConfig() (map[string]any, error) {
	controlConfigOnce.Do(func() {
		data, err := vapdataFS.ReadFile(vapdataDir + "/" + controlConfigFile)
		if err != nil {
			controlConfigErr = fmt.Errorf("read embedded control configuration: %w", err)
			return
		}
		// sigs.k8s.io/yaml decodes via JSON, so numbers, lists and maps come out
		// as the JSON-shaped types CEL expects (the same shape the apiserver hands
		// a paramKind object).
		if err := yaml.Unmarshal(data, &controlConfigVal); err != nil {
			controlConfigErr = fmt.Errorf("parse embedded control configuration: %w", err)
		}
	})
	return controlConfigVal, controlConfigErr
}
