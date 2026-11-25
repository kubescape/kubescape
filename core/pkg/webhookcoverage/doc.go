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
// kind), the operation, and the namespace and name. A cluster-scoped resource
// other than Namespace sets ClusterScoped; a namespaced request that names no
// namespace is never taken to be cluster-scoped. A caller that cannot tell
// whether a resource is namespaced, such as a custom resource without CRD or
// discovery data, sets ScopeUnknown: the three states are never conflated. The
// core Namespace resource is identified by its complete group, version and
// resource, and by Name. Labels of the new object, the
// old object and the request's namespace are optional, and each has a Known
// flag: unsupplied labels are unknown, which is not the same as empty.
//
// # Results
//
// Every webhook gets one of three verdicts:
//
//   - Matched: the supplied request satisfies this webhook's matching
//     criteria. This is not a promise that the webhook receives a call: an
//     earlier admission rejection can stop the request first, an earlier
//     mutation can change the labels a later webhook sees, and matchConditions
//     are not evaluated here, so a webhook that has them is never Matched.
//   - NotMatched: the supplied request does not satisfy this webhook's matching
//     criteria, because some filter definitively rejects it.
//   - Indeterminate: nothing definitively rejects the request, but at least
//     one filter cannot be evaluated from the supplied information. Reasons
//     lists why. Unknown is never reported as NotMatched.
//
// A definite rejection always wins: if the rules reject the request, the
// result is NotMatched even when the namespace selector is indeterminate.
// Reasons explain every verdict except Matched: for NotMatched they name each
// filter that rejected the request, for Indeterminate each that could not be
// decided.
//
// A request that is incomplete or contradicts itself (no operation, version or
// resource) does not undo a definite exclusion: a webhook whose rules could not
// match it whatever the missing part is, such as one with no rules or only for
// another operation, is still NotMatched. The others are Indeterminate.
//
// NewIndex reports malformed selectors and rules with an unrecognised
// operation or scope. Such a webhook is kept and answers Indeterminate when the
// broken part would have to be evaluated; it is not dropped.
//
// # Precision under matchPolicy Equivalent
//
// matchPolicy defaults to Equivalent, so most real webhooks use it. The API
// server then also tries the resources its own equivalent-resource registry
// lists for the request, and that registry is not available here. This package
// does not guess it: when no rule matches the request itself, any rule that
// agrees with it on operation and subresource makes the result Indeterminate,
// whatever the rule says about group, version, resource or scope.
//
// The consequence is a precision loss. With the default policy a caller can
// get many Indeterminate results where the real API server would reach a
// definite NotMatched, for example a rule for "deployments" against a request
// for "secrets". Such a webhook is NotMatched only when every rule differs in
// operation or subresource, or when another filter (namespaceSelector,
// objectSelector, an exempt resource) rejects the request. Exact is not
// affected. Matched is never weakened: a rule that matches the request itself
// is Matched.
//
// # What cannot be evaluated offline
//
//   - matchConditions are CEL expressions that need request context, so a
//     webhook that has them is never Matched, only Indeterminate.
//   - matchPolicy Equivalent (the default): the API server's
//     equivalent-resource registry is not available here, and this package does
//     not assume that equivalent resources keep the plural resource name. See
//     "Precision under matchPolicy Equivalent" above for the rule and its cost.
//   - Namespace labels that were not supplied, other than the automatic
//     kubernetes.io/metadata.name label (which has one exception, below).
//   - Objects whose labels were not supplied, when an objectSelector needs
//     them.
//   - A namespaced request with no namespace, when a namespaceSelector needs it.
//   - A resource whose scope is unknown (ScopeUnknown), when a rule's scope or
//     a namespaceSelector gives a different answer for each scope. A rule that
//     covers both scopes still matches.
//   - Rules holding an operation or scope this package does not recognise.
//   - The automatic kubernetes.io/metadata.name label of a Namespace being
//     created or updated, for validating and mutating webhooks alike. The
//     API server matches such a request on the labels of the object in it
//     (checked in k8s.io/apiserver v0.37.2), but nothing there guarantees that
//     object carries the label: that depends on the Namespace registry in
//     k8s.io/kubernetes, which was not checked. A namespaceSelector on that
//     label is Indeterminate unless the caller supplies the label in
//     ObjectLabels, which is then taken as authoritative and is never
//     overwritten with the request's name. The object's own labels are
//     evaluated even when it has no name yet (generateName): requirements
//     they decide are decided, so a definite rejection is kept and only a
//     requirement that needs the missing label stays Indeterminate. Labels
//     marked unknown are ignored whatever the map holds. For every other
//     request the label is inferred from the namespace name, as
//     core/pkg/namespaceselector does.
//   - The API server drops the authentication and authorization review
//     resources from webhooks only on versions that enable the
//     ExcludeAdmissionWebhookVirtualResources feature gate, so those requests
//     are Indeterminate.
//   - Static, manifest-based webhooks are not part of any API object and are
//     never evaluated here. For the webhook configuration and admission
//     policy kinds the API server skips API-defined webhooks only; static
//     ones may still see them.
//
// # Collection and analysis
//
// Collect reads the validating and mutating webhook configurations of a
// cluster, and Analyze runs collected workloads through Index.Matches with a
// synthetic CREATE request each. Each kind of configuration reports through its
// Source whether it was read: a list that could not be read is never an empty
// one, and an Analysis is only Complete when both kinds and the workloads were
// collected in full. Workload kinds that cannot be analyzed reliably, and
// every other collected kind, are counted in Analysis.Skipped rather than
// dropped. Namespace labels that were not collected stay unknown.
//
// # NotMatched is not a security conclusion
//
// NotMatched only means this particular webhook would not be called for the
// supplied request. Other webhooks, admission policies or built-in admission
// plugins may still cover it, and this package makes no claim about whether a
// workload is protected or admission is bypassed.
package webhookcoverage
