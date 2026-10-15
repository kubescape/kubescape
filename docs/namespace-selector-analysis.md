# Namespace selectors in reachability and exposure analysis

NetworkPolicy peers and Gateway `allowedRoutes` can select a namespace by
`kubernetes.io/metadata.name`. Kubernetes sets this immutable label to the
namespace's name automatically (stable since v1.22). A manifest does not need
to include it explicitly.

The static models use the namespace name for this label, including when the
Namespace object was not collected. A selector for `trusted` therefore matches
an endpoint or route in `trusted` and excludes one in `untrusted`.

Other labels are not inferred. If a selector also requires `team: platform`
and the Namespace was not collected, a matching name alone is insufficient:
NetworkPolicy reachability remains unknown, and Gateway exposure retains its
conservative possible-exposure behavior. A name mismatch conclusively rejects
the selector even when those other labels are unavailable.

Input namespace label maps are not modified. The namespace's actual name takes
precedence over an inconsistent manually supplied name label.

See [Kubernetes automatic namespace labeling](https://kubernetes.io/docs/concepts/overview/working-with-objects/namespaces/#automatic-labelling).
