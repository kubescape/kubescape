package cel

import (
	"bytes"
	"embed"
	"errors"
	"fmt"
	"io"
	"sync"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
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
	// validations run. The offline engine does not evaluate them yet, so we keep
	// them here only so loadVAP can refuse such a policy (see requireSupported)
	// rather than run its validations unconditionally and emit violations live
	// admission would never raise.
	matchConditions []admissionregistrationv1.MatchCondition

	// paramKind mirrors spec.paramKind; nil when the policy declares no params.
	paramKind *admissionregistrationv1.ParamKind

	// matchConstraints mirrors spec.matchConstraints: the GVKs the policy
	// applies to. Offline we use it to scope evaluation (see appliesTo), because
	// the validations self-guard by object.kind and evaluate to true for a
	// non-matching kind, which the scan would otherwise record as a pass live
	// admission never made (the object would not be matched at all).
	matchConstraints *admissionregistrationv1.MatchResources
}

// requireSupported reports whether the offline engine can honor this policy with
// scan/admission parity. matchConditions is an admission-time gate we do not
// evaluate yet; running a gated policy's validations unconditionally would emit
// violations live admission never would, so we refuse the control instead. The
// error maps to the same errored/skipped status a Rego eval error takes, never a
// silent pass or a false violation. Removing this guard is the seam for when the
// evaluator learns to evaluate matchConditions.
func (v *VAP) requireSupported() error {
	if len(v.matchConditions) > 0 {
		return fmt.Errorf("control %q uses spec.matchConditions, which the offline engine does not evaluate yet; refusing it to preserve scan/admission parity", v.ControlID)
	}
	return nil
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
// violation message the same way the apiserver does. matchConditions is carried
// so loadVAP can refuse a gated policy (see requireSupported).
//
// spec.matchConstraints is kept so the scan can scope evaluation to the kinds
// the policy actually applies to (see appliesTo); without it a non-matching
// object slips through the validations' self-guards as a pass. spec.failurePolicy
// is still dropped: eval errors are always mapped to an errored/skipped status
// regardless of failurePolicy, which is the parity-safe direction.
func newVAP(policy *admissionregistrationv1.ValidatingAdmissionPolicy) *VAP {
	vap := &VAP{
		ControlID:        policy.Labels[controlIDLabel],
		PolicyName:       policy.Name,
		matchConditions:  policy.Spec.MatchConditions,
		paramKind:        policy.Spec.ParamKind,
		matchConstraints: policy.Spec.MatchConstraints,
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

// resolveParams returns the value bound to the evaluator's "params" variable. A
// policy with no paramKind gets nil (matching a live binding with no ParamRef).
// Otherwise the whole ControlConfiguration is returned so expressions can reach
// params.settings.<field>, exactly what a live ParamRef would supply.
//
// The returned map is shared across calls (see controlConfig) and is treated as
// read-only: the evaluator only binds it into a CEL activation, which never
// mutates it.
func resolveParams(vap *VAP) (any, error) {
	if vap.paramKind == nil {
		return nil, nil
	}
	params, err := controlConfig()
	if err != nil {
		return nil, err
	}
	return params, nil
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
