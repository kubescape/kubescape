# Request mirrors and external exposure

An HTTPRoute or GRPCRoute `RequestMirror` filter sends copies of incoming
requests to its `requestMirror.backendRef`. The mirror's response is discarded,
but the target still processes externally supplied traffic. Exposure analysis
therefore includes these targets alongside the ordinary forwarding backends.

Both rule-level filters and filters on an active backend reference are read.
A mirror with `percent: 0` or a fraction whose numerator is zero contributes no
exposure. An omitted sampling setting mirrors all requests. A zero-weight
forwarding backend does not activate its own filters; it does not disable
filters belonging to the enclosing rule. Backend-scoped mirrors also retain
their parent's Service reference: if collected Service data shows that the
parent port or protocol cannot receive traffic, its mirrors are excluded.
Missing parent inventory remains conservative, and rule-level mirrors remain
independent of ordinary forwarding backends.

Mirror paths use the same Gateway listener, allowed namespace/kind, hostname,
backend kind/group, and Service-port checks as ordinary backend references.
Repeated references to the same Service still produce one path per route and
hostname. Cross-namespace references are resolved with ReferenceGrants, as
described below.

This is a static analysis of configured intent, not a check that a Gateway
implementation supports or is currently delivering mirrored traffic.

See [Gateway API request mirroring](https://gateway-api.sigs.k8s.io/guides/user-guides/http-request-mirroring/).

## Cross-namespace references and ReferenceGrants

A route's `backendRef` (and a `RequestMirror` target) may name a Service in
another namespace only if a Gateway API `ReferenceGrant` in the Service's
namespace allows it. `analyze_service_exposure` and
`analyze_vulnerability_exposure` collect the cluster's ReferenceGrants and
evaluate each cross-namespace HTTPRoute/GRPCRoute reference against them. A
reference inside the route's own namespace never needs a grant, and a Service
merely existing authorizes nothing.

A grant authorizes a reference when it lives in the target Service's namespace
and has a `from` entry matching the route's group (`gateway.networking.k8s.io`),
kind (`HTTPRoute` or `GRPCRoute`) and namespace, and a `to` entry for the core
group, kind `Service`, whose `name` is either omitted/empty (every Service in
the namespace) or equal to the target's. `from` entries are alternatives, `to`
entries are alternatives, and separate grants add to one another. A backend-
scoped mirror is also dropped when its own parent backend is an unauthorized
cross-namespace reference, since that parent receives no requests.

Each cross-namespace reference ends in one of three states:

| State | When | Result |
| --- | --- | --- |
| Authorized | A matching grant was found | A normal exposure path |
| Unauthorized | Grants were collected and none matches (including a successful, empty list) | No exposure path, not `unclear` |
| Undetermined | Grants could not be collected | No path, reported as `unclear` |

Grants count as collected only when the list succeeded and every grant was
decoded. An API that is not served, a failed list (for example RBAC denial or
connectivity), or a grant that cannot be read all leave authorization
undetermined. They are never read as "no grants". `analyze_service_exposure`
then sets the Service's `unclear` note and a top-level
`reference_grants_unavailable` reason; `analyze_vulnerability_exposure` adds a
per-workload warning. Neither tool fails because of it.

Collecting grants needs `list` on `referencegrants.gateway.networking.k8s.io`,
cluster-wide. Without it, results are the same as before: affected references
stay `unclear`.

Supported versions: `v1` (Gateway API 1.5 and later) is tried first, then
`v1beta1` (v0.7.0 and later). Both share one spec shape. The older `v1alpha2`
version is not read. ReferenceGrants for other reference types (for example a
Gateway's `certificateRefs`) are out of scope, as is cross-namespace Gateway
attachment, which is governed by `allowedRoutes` instead.
