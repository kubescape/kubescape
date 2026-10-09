# RBAC parity tests

`core/pkg/rbacgraph` is a hand-written model of how Kubernetes authorizes RBAC
requests. These tests compare it with Kubernetes itself, so that a difference
shows up as a failing test instead of as a wrong answer from
`analyze_rbac_escalation_paths`.

This is the RBAC-specific first implementation of
[#4071](https://github.com/kubescape/kubescape/issues/4071). The Pod Security
Standards have their own comparison in `core/pkg/pss/upstream_parity_test.go`,
which works differently because an in-process reference exists for them.

## How it works

Each file in `testdata/` is a fixture: a set of RBAC objects and a list of
questions about them. A question is one request by one ServiceAccount, and it
records one answer, the one Kubernetes gives:

```yaml
- id: wildcard-subresource-rule-mints
  serviceAccount: {namespace: lab, name: wildcard}
  mintToken: {namespace: lab, name: target}
  kubernetes: allowed
```

Two test runs use the fixtures.

| | Runs in | Compares | Needs |
| --- | --- | --- | --- |
| `TestKubescapeMatchesRecordedKubernetesAnswers` | `go test ./...` | rbacgraph's answer with the recorded Kubernetes answer | nothing |
| `TestRecordedAnswersMatchKubernetes` | `go test -tags rbacparity`, and the `rbac-parity` workflow | the recorded Kubernetes answer, and rbacgraph's, with a real `kube-apiserver` | the reference binaries |

There is no separate "expected rbacgraph answer" to edit. rbacgraph has to give
the recorded Kubernetes answer, and the recorded answer has to be what the
reference server says. Changing a recorded answer to make a wrong rbacgraph
answer pass therefore fails the reference run.

### Intentional differences

Where rbacgraph differs from Kubernetes on purpose, the question says so:

```yaml
  kubernetes: denied
  intentionalDifference:
    reason: why rbacgraph answers the opposite, and where that was decided
```

- A difference with no `intentionalDifference` fails.
- A difference with one passes.
- An `intentionalDifference` on a question where the two now agree fails, so
  an entry cannot outlive the difference it describes.

No fixture records one today.

Not every deliberate difference can be a fixture. rbacgraph treats the right to
impersonate the group `system:masters` as cluster-admin on its own, while the
API server refuses to impersonate a group without also impersonating a user.
There is no single request that asks Kubernetes the question rbacgraph answers
there, so that behaviour stays covered by rbacgraph's unit tests
(`TestAnalyzeEscalation_ImpersonateSystemMastersIsImmediateClusterAdmin`)
rather than being forced into a comparison that would compare two different
things.

## The questions

A question maps to one request to the API server and to one kind of rbacgraph
escalation edge. Only single-hop questions are asked: a multi-hop verdict such
as `cluster_admin_equivalent` has no single request to compare with.

| Question | Request made as the ServiceAccount | rbacgraph edge |
| --- | --- | --- |
| `mintToken` | `POST` `serviceaccounts/<name>/token` | `mint-serviceaccount-token` to that ServiceAccount |
| `rewriteRole` | dry-run `PUT` (`verb: update`) or `PATCH` (`verb: patch`) of the Role with a rule granting everything | `escalate-verb` whose `Target` covers the Role, and which still exists when the verb the question does not use is removed from the subject's rules |
| `bindClusterRole` | dry-run `POST` of a ClusterRoleBinding, or of a RoleBinding in `namespace`, binding the ClusterRole to the ServiceAccount itself | `bind-verb` whose `Target` is the ClusterRole and whose `Scope` is `namespace` |

Things to keep in mind when writing one:

- The reference asks with a token issued for the ServiceAccount, so the
  ServiceAccount must be one of the fixture's objects. Questions asked as a
  User are not supported: the reference would need a second way to
  authenticate. rbacgraph's handling of a User that carries a ServiceAccount's
  username is covered by its unit tests.
- `mintToken` must name a ServiceAccount other than the one asking. Kubernetes
  allows a ServiceAccount to mint a token for itself when a rule covers it,
  but that is not an escalation, and rbacgraph deliberately has no edge from a
  subject to itself. The question would compare an authorization with an
  escalation, so loading the fixture fails. It is not something to record as
  an `intentionalDifference`.
- rbacgraph does not distinguish `update` from `patch`: either one, with
  `escalate`, gives the same edge. Kubernetes does, so the adapter looks for
  the edge with the verb the question does not use removed from the subject's
  rules. A subject that holds only `update` is denied a `patch` on both sides.
- Kubernetes lets anyone bind a role whose permissions they already hold. For
  `bindClusterRole`, give the ClusterRole a permission the subject does not
  have, or the question is not about the `bind` verb.
- Only a 403 counts as `denied`. Any other error fails the run, so a typo in an
  object name cannot pass as a denial.
- A fixture may contain Namespaces, ServiceAccounts, Roles, ClusterRoles,
  RoleBindings and ClusterRoleBindings, which is what rbacgraph collects.
- Every fixture gets a control plane of its own, so fixtures cannot affect
  each other.

## Adding a case

1. Add a file to `testdata/`, or a question to an existing fixture, with the
   answer you believe Kubernetes gives.
2. Run the reference tests. If the recorded answer is wrong they say what the
   server answered.
3. If rbacgraph disagrees with Kubernetes, fix rbacgraph, or record an
   `intentionalDifference` with the reason.

A case of an existing kind needs no Go code. A new kind of question needs a
request in `reference_test.go` and a mapping to an edge in `adapter.go`.

## The reference

`reference.env` pins the exact `kube-apiserver` release, the `etcd` release
that Kubernetes version uses, and the SHA-256 checksum of each download. It is
read by `fetch-reference.sh` and by the tests:

- `TestReferenceTracksGoMod` (ordinary run) fails when the pinned Kubernetes
  minor is not the minor of `k8s.io/api` in `go.mod`.
- The reference tests fail unless the server they started reports exactly the
  pinned version.

The servers are started with
[envtest](https://pkg.go.dev/sigs.k8s.io/controller-runtime/pkg/envtest): a
real `kube-apiserver` and `etcd` run as ordinary processes, with no kubelet, no
container runtime and no privileges. RBAC authorization and the escalation
checks on Role and binding writes both happen inside the API server, so that
is all these questions need.

### Running the reference tests

On Linux:

```sh
export KUBEBUILDER_ASSETS="$(mktemp -d)"
core/pkg/rbacgraph/parity/fetch-reference.sh "$KUBEBUILDER_ASSETS"
go test -tags rbacparity -count=1 -v ./core/pkg/rbacgraph/parity/...
```

Kubernetes publishes `kube-apiserver` for Linux only. On macOS, use the envtest
build of the same minor and say that the patch release may differ:

```sh
export KUBEBUILDER_ASSETS="$(go run sigs.k8s.io/controller-runtime/tools/setup-envtest@latest use 1.37.x -p path)"
RBAC_PARITY_ALLOW_OTHER_PATCH=1 go test -tags rbacparity -count=1 -v ./core/pkg/rbacgraph/parity/...
```

That run prints a warning: it is useful while writing a fixture, but only a
run against the pinned release verifies one. CI never sets the variable.

### Moving to a new Kubernetes version

Change the versions and checksums in `reference.env` (the file says where the
checksums are published) and run the reference tests. A fixture whose recorded
answer the new server no longer gives fails with both answers; decide whether
rbacgraph should follow, and update the fixture.
