# Request mirrors and external exposure

An HTTPRoute or GRPCRoute `RequestMirror` filter sends copies of incoming
requests to its `requestMirror.backendRef`. The mirror's response is discarded,
but the target still processes externally supplied traffic. Exposure analysis
therefore includes these targets alongside the ordinary forwarding backends.

Both rule-level filters and filters on an active backend reference are read.
A mirror with `percent: 0` or a fraction whose numerator is zero contributes no
exposure. An omitted sampling setting mirrors all requests. A zero-weight
forwarding backend does not activate its own filters; it does not disable
filters belonging to the enclosing rule.

Mirror paths use the same Gateway listener, allowed namespace/kind, hostname,
backend kind/group, and Service-port checks as ordinary backend references.
Repeated references to the same Service still produce one path per route and
hostname. Cross-namespace references remain uncertain because this model does
not collect ReferenceGrant objects.

This is a static analysis of configured intent, not a check that a Gateway
implementation supports or is currently delivering mirrored traffic.

See [Gateway API request mirroring](https://gateway-api.sigs.k8s.io/guides/user-guides/http-request-mirroring/).
