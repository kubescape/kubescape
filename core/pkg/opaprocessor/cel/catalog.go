package cel

import (
	"fmt"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
)

// This file exposes bundle metadata to callers outside the engine, so the
// embedded VAP YAML is the single source of truth for facts like "which policy
// implements control C-0016" and "does it need params" — the same facts cmd/vap
// used to keep in hand-typed maps that drifted from the library (issue #2369).
//
// These helpers deliberately bypass loadVAP's requireSupported gate: a policy
// the offline engine refuses to evaluate (e.g. one gated on matchConditions) is
// still perfectly valid to deploy and bind on a cluster, where live admission
// evaluates the gate itself. Refusing to answer metadata questions about it
// would wrongly block that workflow.

// PolicyNameForControl returns the metadata.name of the ValidatingAdmissionPolicy
// implementing a control (e.g. C-0016 ->
// kubescape-c-0016-allow-privilege-escalation), read from the embedded bundle.
// It errors when the control has no policy in the bundle.
func PolicyNameForControl(controlID string) (string, error) {
	vap, err := lookupVAP(controlID)
	if err != nil {
		return "", err
	}
	return vap.PolicyName, nil
}

// ParamKindForControl returns the spec.paramKind of the control's policy, nil
// when the policy declares no params. A non-nil paramKind means a binding for
// this policy needs a ParamRef to be functional. It errors when the control has
// no policy in the bundle.
func ParamKindForControl(controlID string) (*admissionregistrationv1.ParamKind, error) {
	vap, err := lookupVAP(controlID)
	if err != nil {
		return nil, err
	}
	return copyParamKind(vap.paramKind), nil
}

// ParamKindForPolicy is the name-keyed variant of ParamKindForControl. Unlike
// the control lookup it covers every policy in the bundle, including the
// cluster-scoped helpers that carry no controlId. found reports whether the
// name is in the bundle at all: a caller handed an arbitrary policy name (e.g.
// cmd/vap --policy pointing at a policy outside the library) gets found=false
// and should skip paramKind-based checks rather than fail.
func ParamKindForPolicy(policyName string) (paramKind *admissionregistrationv1.ParamKind, found bool, err error) {
	catalog, err := getVAPCatalog()
	if err != nil {
		return nil, false, err
	}
	if _, dup := catalog.dupNames[policyName]; dup {
		return nil, false, fmt.Errorf("policy %q is defined more than once in the VAP bundle; refusing it rather than pick one", policyName)
	}
	vap, ok := catalog.byName[policyName]
	if !ok {
		return nil, false, nil
	}
	return copyParamKind(vap.paramKind), true, nil
}

// copyParamKind hands callers their own copy so the catalog's parsed policies
// stay immutable.
func copyParamKind(paramKind *admissionregistrationv1.ParamKind) *admissionregistrationv1.ParamKind {
	if paramKind == nil {
		return nil
	}
	c := *paramKind
	return &c
}
