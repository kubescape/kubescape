// Package webhookcoverage evaluates whether a synthetic admission request
// would be sent to each webhook of supplied ValidatingWebhookConfiguration and
// MutatingWebhookConfiguration objects.
//
// It is an offline matcher, not a live API server. Rule and object-selector
// matching call the k8s.io/apiserver predicates the API server itself uses,
// and namespace selectors go through core/pkg/namespaceselector.
//
// # Required information
//
// A Request names the API coordinates (group, version, resource, subresource,
// kind), the operation, and the namespace and name. Labels of the new object,
// the old object and the request's namespace are optional, and each has a
// Known flag: unsupplied labels are unknown, which is not the same as empty.
//
// # Results
//
// Every webhook gets one of three verdicts:
//
//   - Matched: every filter is satisfied, so the API server would evaluate
//     the webhook's matchConditions (if any) and then call it.
//   - NotMatched: some filter definitively rejects the request, so the API
//     server would not call this webhook for it.
//   - Indeterminate: nothing definitively rejects the request, but at least
//     one filter cannot be evaluated from the supplied information. Reasons
//     lists why. Unknown is never reported as NotMatched.
//
// A definite rejection always wins: if the rules reject the request, the
// result is NotMatched even when the namespace selector is indeterminate.
//
// # What cannot be evaluated offline
//
//   - matchConditions are CEL expressions that need request context, so a
//     webhook that has them is never Matched, only Indeterminate.
//   - matchPolicy Equivalent (the default) also matches equivalent
//     group/versions of a resource. The equivalence registry lives in the API
//     server, so a rule that differs from the request only in group or
//     version is Indeterminate.
//   - Namespace labels that were not supplied, other than the automatic
//     kubernetes.io/metadata.name label.
//   - Objects whose labels were not supplied, when an objectSelector needs
//     them.
//   - The API server drops the authentication and authorization review
//     resources from webhooks only on versions that enable the
//     ExcludeAdmissionWebhookVirtualResources feature gate, so those requests
//     are Indeterminate.
//   - Static, manifest-based webhooks are not part of any API object and are
//     never evaluated here. For the webhook configuration and admission
//     policy kinds the API server skips API-defined webhooks only; static
//     ones may still see them.
//
// # NotMatched is not a security conclusion
//
// NotMatched only means this particular webhook would not be called for the
// supplied request. Other webhooks, admission policies or built-in admission
// plugins may still cover it, and this package makes no claim about whether a
// workload is protected or admission is bypassed.
package webhookcoverage
