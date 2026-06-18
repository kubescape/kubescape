// Package cel implements the CEL evaluation engine for Kubescape. It compiles
// and evaluates ValidatingAdmissionPolicy (VAP) expressions offline, against
// resources scanned from files, so that a VAP behaves the same way in a scan as
// it does at live admission.
package cel

import (
	"github.com/google/cel-go/cel"
	"k8s.io/apiserver/pkg/cel/environment"
)

// newEnv builds the CEL environment used to compile and evaluate VAP
// expressions offline.
//
// It extends apiserver's base env set rather than hand-picking CEL libraries.
// The base set carries both the function library set (so quantity(), isIP(),
// format.*, etc. exist) and the version gating that a real cluster applies to a
// VAP. That is what guarantees a VAP behaves identically offline (in our scan)
// and at live admission. Hand-assembling the libraries ourselves would risk a
// function being present in one place and absent in the other, silently
// breaking the equivalence guarantee. Always extend the base set; never replace
// it.
func newEnv() (*cel.Env, error) {
	// Compatibility version pins the CEL feature/library set to what the
	// apiserver guarantees, so scan and admission agree on what is available.
	compatVersion := environment.DefaultCompatibilityVersion()

	// The base set carries the apiserver CEL libraries, language settings and
	// runtime cost limits. It declares no variables; we add the VAP variables
	// on top of it.
	baseEnvSet := environment.MustBaseEnvSet(compatVersion)

	// Declare the VAP variables. They are declared dynamic because objects are
	// bound from YAML as map[string]any rather than custom Go types.
	//
	//   - object    : the K8s resource being scanned.
	//   - oldObject : declared here and bound to null offline, so a CREATE
	//                 (request.operation=CREATE) has the same null oldObject it
	//                 would have at live admission.
	//   - params    : resolved from the control configuration; declared here so
	//                 params.* references compile.
	//   - request   : stubbed offline (operation=CREATE, empty userInfo);
	//                 declared here so request.* references compile.
	//   - variables : a dynamic selector so validations referencing
	//                 variables.<name> compile; values are injected per-object
	//                 at eval time.
	//
	// authorizer is deliberately NOT declared: it cannot be resolved offline, so
	// a policy referencing authorizer should fail to compile and get skipped
	// rather than produce a wrong verdict.
	extended, err := baseEnvSet.Extend(environment.VersionedOptions{
		// IntroducedVersion is required. Pinning it to the compatibility
		// version itself means these variables are included at this version in
		// both the NewExpressions and StoredExpressions environments.
		IntroducedVersion: compatVersion,
		EnvOptions: []cel.EnvOption{
			cel.Variable("object", cel.DynType),
			cel.Variable("oldObject", cel.DynType),
			cel.Variable("params", cel.DynType),
			cel.Variable("request", cel.DynType),
			cel.Variable("variables", cel.DynType),
		},
	})
	if err != nil {
		return nil, err
	}

	// StoredExpressions is the mode for compiling an already-authored policy
	// (the VAP YAML we load from cel-admission-library), as opposed to
	// NewExpressions which is used when validating a brand new policy.
	return extended.Env(environment.StoredExpressions)
}
