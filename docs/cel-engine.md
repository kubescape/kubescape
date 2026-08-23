# CEL rule engine

Kubescape evaluates `ValidatingAdmissionPolicy` (VAP) expressions offline, alongside
the existing OPA/Rego engine, so that a policy behaves the same way in a scan as it
does at live admission.

This document describes the engine as built. It is the companion to the tracking
issue [#2001](https://github.com/kubescape/kubescape/issues/2001).

## Motivation

Kubescape could already *deploy* VAP resources to a cluster (`kubescape vap
deploy-library`), but it could not *evaluate* them. Scanning and admission were
separate code paths with no relationship between their verdicts, so nothing
guaranteed that a resource passing `kubescape scan` would be admitted by a cluster
enforcing the same policy.

Kubernetes evaluates VAP policies natively using CEL. If Kubescape evaluates the
same policy documents with the same CEL environment, the two verdicts can be made
to agree, and that agreement is the point of the engine.

## How it fits into a scan

`core/pkg/opaprocessor/processorhandler.go` already dispatched on
`rule.RuleLanguage`. CEL is a second branch alongside Rego:

```text
processControl(control)
  └─ processRule(rule, control.ControlID)
       └─ runOPAOnSingleRule(...)
            ├─ RegoLanguage → runRegoOnK8s(...)
            └─ CELLanguage  → runCELOnK8s(..., controlID, ...)
```

Everything downstream of the rule is unchanged. CEL violations are mapped to
`reporthandling.RuleResponse` values with the same shape Rego produces, so
reporting, scoring, exceptions and output formats need no CEL awareness.

## Marking a rule as CEL

A rule opts in through the existing language field:

```json
{
  "name": "rule-allow-privilege-escalation",
  "ruleLanguage": "CEL"
}
```

`reporthandling.CELLanguage` is defined in
[`opa-utils`](https://github.com/kubescape/opa-utils). A rule with any other
language continues through the Rego path untouched.

A CEL rule must not also declare a `ResourceEnumerator`. It scopes through the
policy's `matchConstraints` instead, and routing it through the enumerator would
run its validations *as* the enumerator, silently dropping every compliant
resource. `enumerateData` rejects the combination rather than trusting it not to
happen.

### Trying it before regolibrary marks anything CEL

No rule shipped in regolibrary carries `ruleLanguage: CEL` yet, so a plain
`kubescape scan control <ID>` takes the Rego path. Until
[#2002](https://github.com/kubescape/kubescape/issues/2002) lands, reaching the
engine means scanning from a control document you have marked yourself:

```sh
kubescape download control C-0016 --output C-0016.json
# edit that file: set "ruleLanguage": "CEL" on each of its rules
grep ruleLanguage C-0016.json         # confirm the edit took
kubescape scan control C-0016 --use-from C-0016.json
```

The `grep` is worth doing. A Rego run of the same control prints an identical
results table, so a scan that skipped the edit looks exactly like a scan that
used it.

### How the engine finds the policy

The rule carries no reference to a policy document. `PolicyRule` embeds
`PortalBase`, which has no control ID field, and adding one would mean changing a
shared type and populating it per rule in regolibrary.

Instead the control ID is threaded down the call path. `control.ControlID` is
already in scope in `processControl`, so it is passed through `processRule` and
`runOPAOnSingleRule` into `runCELOnK8s`, which hands it to the loader. All of
those functions are unexported and internal to Kubescape. Rego callers pass an
empty string.

The loader looks the control ID up against the `controlId` label on each policy in
the bundle:

```yaml
metadata:
  name: kubescape-c-0016-allow-privilege-escalation
  labels:
    controlId: "C-0016"
```

A policy with no `controlId` label stays out of the control index but remains
reachable by name, which is what the cluster-scoped helper policies need. If two
policies claim the same control ID, neither wins: the ID is dropped from the index
and reported as a duplicate, so one malformed policy cannot silently shadow
another.

## Where policies and params come from

The VAP documents and their configuration are vendored into the repository and
embedded into the binary with `//go:embed`, under
`core/pkg/opaprocessor/cel/vapdata/`:

| File | Purpose |
|---|---|
| `kubescape-validating-admission-policies.yaml` | the policies themselves |
| `basic-control-configuration.yaml` | values bound to `params` |
| `policy-configuration-definition.yaml` | the `ControlConfiguration` CRD, used by `deploy-library` |

The copy is refreshed from a pinned `cel-admission-library` release rather than
maintained by hand:

```sh
make sync-vap        # honours CEL_LIBRARY_VERSION in the Makefile
```

Pinning keeps the vendored bundle reproducible, and bumping the pin is a reviewable
change rather than a silent drift. `kubescape vap deploy-library` serves this same
embedded bundle by default, so what a scan evaluates and what a cluster gets
deployed come from one source.

### params

A policy declaring a `paramKind` has its `params` resolved from
`basic-control-configuration.yaml`, matching what a live binding's `paramRef`
would supply. A policy with no `paramKind` resolves to nil params, matching a
binding with no `paramRef`.

## The evaluation environment

The environment extends the apiserver's own base environment set
(`k8s.io/apiserver/pkg/cel/environment`) rather than assembling CEL libraries by
hand. The base set carries both the function library set and the version gating a
real cluster applies, so a function cannot be present in one place and absent in
the other. Policies are compiled in `StoredExpressions` mode, which is the mode
the apiserver uses for an already-authored policy.

Six variables are declared:

| Variable | Offline | At admission |
|---|---|---|
| `object` | the scanned resource | the resource being admitted |
| `params` | from `basic-control-configuration.yaml` | from the binding's `paramRef` |
| `oldObject` | `null` | previous state |
| `request` | stubbed, `operation=CREATE`, empty `userInfo` | the full admission request |
| `namespaceObject` | the resource's Namespace when the scan collected it, else `null` | the resource's Namespace, `null` when cluster-scoped |
| `variables` | the policy's own `variables:` block | same |

`authorizer` is deliberately **not** declared. It cannot be resolved offline, so a
validation referencing it fails to compile, and every resource that validation was
evaluated against is reported as skipped rather than given a verdict the scan
cannot justify. The skip is per resource: the other validations in the same policy
still reach verdicts, and a violation confirmed by one of them stands.

### Why oldObject is null rather than absent

Kubescape scans files, so every resource is modelled as a fresh CREATE. A CREATE
at live admission has a null `oldObject`, so binding null is the parity-preserving
choice. It is bound explicitly rather than left out of the activation: the variable
is declared on the environment, and a declared variable missing from the activation
errors at evaluation time instead of evaluating as null.

The same reasoning applies to `request`. Every field a real `AdmissionRequest`
exposes is populated, with zero values where the scan has nothing real, because
`request` is a dynamic type and selecting an absent key is a runtime error rather
than null.

### Compiling and caching

Compiling an expression is the expensive step; running the compiled program is
cheap. A scan runs the same bundle expressions against every scanned object, so
compiled programs are memoized by expression text and reused for the whole scan.

Compile failures are cached alongside successes, because a broken expression stays
broken regardless of which object it runs against. Evaluation failures are never
cached, because they depend on the object: a field missing on one resource may be
present on the next.

## Which resources a policy is evaluated against

VAP validations commonly self-guard on kind:

```cel
object.kind != 'Pod' || object.spec.containers.all(c, ...)
```

Evaluating such an expression against a ConfigMap returns true. Recording that as a
pass would report a result the cluster never produced, because at admission the
policy would not have been handed the object at all.

So `spec.matchConstraints` is honoured before evaluation. An object outside the
policy's constraints is **excluded** from the results rather than marked skipped,
which mirrors admission never matching it, and avoids inflating skip counts
wherever a regolibrary rule's own match is broader than the policy's.

Matching covers everything on `matchConstraints` whose input the scanned object
itself carries:

- the resource rules: `apiGroups`, `apiVersions`, `resources`, honouring `*` and
  `excludeResourceRules`
- each rule's `operations`, against the modelled CREATE, so a rule scoped only to
  UPDATE or DELETE does not match
- each rule's `resourceNames`, against `metadata.name`
- `objectSelector`, against the object's own labels

`matchPolicy` needs no handling. `Equivalent` matching only widens a rule across
API conversions, and a scan never converts: the object is matched at the exact
group and version it was scanned at.

### Match conditions

`spec.matchConditions` is a second gate, applied after `matchConstraints`. At
admission a policy whose conditions do not all hold is skipped and none of its
validations run, so offline an object the gate turns away is excluded exactly as
an unmatched one is.

Three details of the gate follow the apiserver's matcher rather than the obvious
reading:

- **A false condition outranks one that errored**, whichever order they appear
  in. The apiserver evaluates every condition, collects the errors, and still
  returns not-matched the moment it sees a false. Returning on the first error
  instead would deny an object under `Fail` that admission simply skips.
- **The gate gets its own cost budget and its own activation.** The apiserver's
  matcher runs on a fresh matchConditions budget and discards the remainder, so
  charging the validations for the gate would exhaust a scan a cluster handles
  fine. Separate activations because `variables` memoize per activation, and
  sharing one would hand the validations work the gate already paid for.
- **`namespaceObject` is bound to null inside the gate**, even when the scan
  captured a real Namespace, because the apiserver's matcher passes a nil
  namespace while the validations that follow get the resolved one.

A gate that reaches no verdict follows `spec.failurePolicy` the way a validation
does: `Fail` denies, `Ignore` skips the policy. An offline-only failure, meaning a
condition that will not compile, an exhausted budget or a cancelled scan, stays an
unknown verdict either way.

## Policies the engine refuses

One construct causes a policy to be refused at load rather than evaluated. Refusal
surfaces as a skip, which is loud, instead of a verdict that might silently differ
from admission.

**`matchConstraints.namespaceSelector`** reads the *namespace's* labels. The scan
only has those when some control's match happened to collect Namespace objects.
Evaluating the selector against an absent namespace would either exempt objects
admission matches or match objects admission exempts, depending on which way the
selector points. Both are silent parity breaks. A selector that narrows nothing is
not a refusal: an absent one, and the empty one the apiserver defaults an omitted
selector to, both match every object.

The distinction that governs it: a `matchConstraints` knob whose input the scanned
object carries is evaluated; one whose input the scan cannot guarantee to have is
refused.

Refusal is not free. A load failure makes the whole control error, which marks
every resource skipped for that control across the scan. So the refusal set is kept
as small as correctness allows.

## The equivalence guarantee

> For a policy scoped to `object` and `params`, if `kubescape scan` passes a
> resource, live admission of that resource passes too.

Several pieces hold this up:

- the same CEL environment and compatibility version as the apiserver, so the same
  functions exist and behave the same way
- the whole policy document is evaluated, with its `variables:` and
  `messageExpression` intact, rather than an expression extracted from it
- `matchConstraints` scoping, so the engine only judges what admission would judge
- a shared cost budget per policy per object, mirroring the apiserver's
  `RuntimeCELCostBudget`. Without it a policy whose expressions individually fit
  under the per-call limit but together exceed the budget would be accepted offline
  and rejected on a cluster
- lazily evaluated `variables`, matching admission, so an unreferenced broken
  variable is ignored and a broken referenced one fails only the validations that
  reference it

An expression that errors, or returns a non-boolean, sets an error on the result
rather than passing. An unknown verdict is never reported as a pass.

What becomes of that error follows the policy's `spec.failurePolicy`, as it does
at admission. Under `Fail`, which is the default and what every policy in the
bundle uses, an errored expression denies the object, so the scan reports a
failure whose message is the error instead of quietly downgrading it to a skip.
Under `Ignore` the resource is skipped. Compile failures, budget exhaustion and
cancellation stay unknown verdicts either way: a cluster never produces them, so
there is no admission outcome to mirror.

### Verifying it against a cluster

The guarantee is checked by hand rather than in CI, since it needs a cluster:

1. create a cluster on a version where VAP is GA (1.30 or later)
2. apply one policy and a binding with `validationActions: [Deny]`
3. apply a fixture that should fail and one that should pass, confirming the
   cluster rejects the first and admits the second
4. scan those same two files through the engine, using the marked control
   document from "Trying it before regolibrary marks anything CEL" above. A
   plain `kubescape scan control <ID>` takes the Rego path and proves nothing
   here
5. confirm all four verdicts agree

## Known gaps

These are gaps in what a scan can know, not defects. In most of them the engine
reports a skip rather than a verdict.

**`authorizer`** is not available offline. A validation performing authorization
checks fails to compile, and each resource it was evaluated against is skipped.
The skip is per resource, not control-wide: only a policy that fails to load
skips a whole control.

**`request.userInfo`** is empty. The identity performing an operation does not
exist in a file scan.

**`namespaceObject` is conditional.** It binds to a real Namespace only when the
scan happened to collect Namespace objects, and namespace collection is driven by
the framework's own policy matches rather than by what the CEL policies need. The
same control can therefore see a real Namespace under one framework and null under
another. A policy that null-guards its access reaches a verdict that may not be the
one admission would reach. One that selects into `namespaceObject` unguarded gets
an evaluation error, and under `failurePolicy: Fail` that is reported as a failure,
so an uncollected Namespace can produce a finding a cluster would not. This is the
one gap here that is not a safe skip. Nothing in the bundle reads `namespaceObject`
today, so it is latent. Making it unconditional means guaranteeing Namespace
collection whenever a loaded policy needs it.

**Only CREATE is modelled.** A policy whose resource rules exclude CREATE is never
matched offline.

## Results and remediation

CEL violations become `RuleResponse` values with the same shape as Rego's, so
nothing downstream changes.

### Messages

A violation's message follows the same precedence the apiserver's validator uses:
the validation's `messageExpression` if it has one and it evaluates, then its
static `message`, then a `failed expression: <expr>` fallback.

A `messageExpression` that fails to evaluate falls back to the next option rather
than turning the result into an error. The verdict has already been reached at that
point, and failing to render an explanation is not grounds for discarding it. The
message expression draws from the same cost budget as the validations, as it does
at admission.

### Remediation paths

VAP validations carry no path information: a validation has an expression, a
message, a `messageExpression` and a reason, and nothing that says which field of
the object was at fault. Remediation paths are therefore derived by walking the
compiled CEL AST for selector chains rooted at `object`, then resolving list
indices against the object being reported on.

Because `kubescape fix` writes YAML from these paths, a wrong path is worse than no
path. Paths are only reported when the walk can justify them, and a path with no
justified value is reported for review rather than as a fix.

Errors are scoped as narrowly as the failure allows. A single object that fails to
evaluate marks that object skipped, and does not erase confirmed violations for the
other objects in the batch. A policy that fails to load is what marks the whole
control skipped.

## Out of scope

- deprecating or replacing the Rego engine
- `MutatingAdmissionPolicy`
- reading VAP resources already deployed to a live cluster
- policies using `authorizer` or `request.userInfo`

## Related

- [#2001](https://github.com/kubescape/kubescape/issues/2001) tracks the engine
- [#2002](https://github.com/kubescape/kubescape/issues/2002) tracks migrating
  existing regolibrary controls to CEL
- [`cel-admission-library`](https://github.com/kubescape/cel-admission-library) is
  the source of the policy bundle
