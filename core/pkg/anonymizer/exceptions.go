package anonymizer

import (
	"github.com/armosec/armoapi-go/armotypes"
)

// exceptionTransformer anonymizes the exception policies attached to rules.
//
// An exception reaches a report as rule.Exception, a whole PostureExceptionPolicy.
// Inline exceptions are named "inline-" + the resource ID and copy the
// kubescape.io/skip-reason annotation as their reason, and every exception's
// resource designators spell out the names and namespaces it matched, so left
// alone the policy carries the identifiers the rest of the session hides.
//
// Results are memoized because the same exception is attached to every rule it
// matched, and a randomizing transformer such as encryption would otherwise give
// each copy a different value, which readers could no longer recognize as one
// exception.
type exceptionTransformer struct {
	transformer Transformer
	memo        map[string]string
}

func newExceptionTransformer(transformer Transformer) *exceptionTransformer {
	return &exceptionTransformer{transformer: transformer, memo: make(map[string]string)}
}

func (t *exceptionTransformer) transform(prefix, value string) (string, error) {
	if value == "" {
		return "", nil
	}
	key := prefix + "\x00" + value
	if transformed, ok := t.memo[key]; ok {
		return transformed, nil
	}
	transformed, err := t.transformer.Transform(prefix, value)
	if err != nil {
		return "", err
	}
	t.memo[key] = transformed
	return transformed, nil
}

// policy returns an anonymized copy of exception. It is an allowlist: only what
// readers need to tell exceptions apart and to recompute the rule's status
// survives. The name, GUID and reason are transformed; the action, the
// framework/control/rule tuples and the expiration are kept because they carry no
// resource identity and drive the effective status; everything else, the resource
// designators, label selector, attributes and author, is dropped.
func (t *exceptionTransformer) policy(exception armotypes.PostureExceptionPolicy) (armotypes.PostureExceptionPolicy, error) {
	var out armotypes.PostureExceptionPolicy
	var err error
	if out.Name, err = t.transform("exception", exception.Name); err != nil {
		return out, err
	}
	if out.GUID, err = t.transform("exception-guid", exception.GUID); err != nil {
		return out, err
	}
	if exception.Reason != nil {
		reason, err := t.transform("exception-reason", *exception.Reason)
		if err != nil {
			return out, err
		}
		out.Reason = &reason
	}
	out.PolicyType = exception.PolicyType
	out.Actions = append([]armotypes.PostureExceptionPolicyActions(nil), exception.Actions...)
	out.PosturePolicies = append([]armotypes.PosturePolicy(nil), exception.PosturePolicies...)
	out.ExpirationDate = exception.ExpirationDate
	return out, nil
}

func (t *exceptionTransformer) policies(list []armotypes.PostureExceptionPolicy) ([]armotypes.PostureExceptionPolicy, error) {
	if len(list) == 0 {
		return list, nil
	}
	out := make([]armotypes.PostureExceptionPolicy, 0, len(list))
	for _, exception := range list {
		anonymized, err := t.policy(exception)
		if err != nil {
			return nil, err
		}
		out = append(out, anonymized)
	}
	return out, nil
}
