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

	// paramKind mirrors spec.paramKind; nil when the policy declares no params.
	paramKind *admissionregistrationv1.ParamKind
}

// vapIndex is built once from the embedded bundle and reused. Parsing every
// document on each lookup would be wasteful, and the bundle never changes at
// runtime, so a lazily-built controlID -> VAP map is enough.
var (
	vapIndexOnce sync.Once
	vapIndex     map[string]*VAP
	vapIndexErr  error
)

// loadVAP returns the policy for a control ID (threaded in from processControl,
// never read off a rule). It fails when the control is absent from the embedded
// bundle rather than silently returning nothing, so a scan cannot quietly skip a
// control it thinks it covers.
func loadVAP(controlID string) (*VAP, error) {
	vapIndexOnce.Do(buildVAPIndex)
	if vapIndexErr != nil {
		return nil, vapIndexErr
	}
	vap, ok := vapIndex[controlID]
	if !ok {
		return nil, fmt.Errorf("no %s for control %q in embedded bundle", vapKind, controlID)
	}
	return vap, nil
}

// buildVAPIndex reads the embedded bundle and hands the bytes to parseVAPBundle.
// Splitting the two keeps the parsing logic testable with in-memory bundles.
func buildVAPIndex() {
	data, err := vapdataFS.ReadFile(vapdataDir + "/" + vapBundleFile)
	if err != nil {
		vapIndexErr = fmt.Errorf("read embedded VAP bundle: %w", err)
		return
	}
	vapIndex, vapIndexErr = parseVAPBundle(data)
}

// parseVAPBundle turns a multi-document bundle into the controlID -> VAP map.
//
// It consumes only v1 ValidatingAdmissionPolicy documents and skips everything
// else. The bundle is a mixed stream synced from cel-admission-library, which
// also ships ValidatingAdmissionPolicyBinding (and blank) documents; failing the
// whole index over one document we do not consume would take the entire engine
// down on a routine `make sync-vap`, so a foreign kind is skipped, not fatal.
// Policies with no controlId label (cluster-scoped helper policies) are skipped
// too: they are not addressable by control and the scan never asks for them.
//
// A duplicate control ID is still an error: that is two policies fighting over a
// control we do consume, and picking one silently would hide a real bundle bug.
func parseVAPBundle(data []byte) (map[string]*VAP, error) {
	index := make(map[string]*VAP)
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

		controlID := policy.Labels[controlIDLabel]
		if controlID == "" {
			continue
		}
		if _, dup := index[controlID]; dup {
			return nil, fmt.Errorf("duplicate control %q in VAP bundle", controlID)
		}
		index[controlID] = newVAP(&policy)
	}

	return index, nil
}

// newVAP flattens a parsed policy into the evaluator's structs. The message and
// messageExpression travel with each validation so the evaluator can resolve the
// violation message the same way the apiserver does.
func newVAP(policy *admissionregistrationv1.ValidatingAdmissionPolicy) *VAP {
	vap := &VAP{
		ControlID:  policy.Labels[controlIDLabel],
		PolicyName: policy.Name,
		paramKind:  policy.Spec.ParamKind,
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
