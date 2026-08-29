# Rego fixtures for the Rego-versus-CEL parity harness

`rules/` is a copy of the matching directories from
[kubescape/regolibrary](https://github.com/kubescape/regolibrary) at tag
**v2.0.33**, kept only for the rules behind the controls that also ship as a
ValidatingAdmissionPolicy in the vendored CEL bundle.

The harness that reads it is `processorhandler_regocelparity_test.go`. It runs
each control's Rego rules and its CEL policy over the same objects and compares
the per-resource verdicts, so it needs the Rego source and something to feed
both sides. regolibrary's own rule tests are that something: they are the cases
the rule authors picked as meaningful, which makes them harder to argue with
than fixtures written alongside the CEL policy.

## Layout

`default-config-inputs.json` is regolibrary's, copied unchanged. It is the
`postureControlInputs` a scan hands the Rego side when nothing has been
overridden. The CEL side is not configured from it: its policies take the params
the bundle ships, which is the same split a real scan has, so configuration that
has drifted between the two libraries shows up as a disagreement rather than
being papered over.

Then per rule, mirroring regolibrary so a refresh is close to a plain copy:

```text
rules/<rule-name>/rule.metadata.json    the rule minus its Rego source
rules/<rule-name>/raw.rego              becomes PolicyRule.Rule
rules/<rule-name>/filter.rego           becomes PolicyRule.ResourceEnumerator (only some rules have one)
rules/<rule-name>/test/<case>/input/*   manifests, one object per file
rules/<rule-name>/test/<case>/input.yaml  same thing for cases regolibrary wrote as a single file
```

## What is dropped, and why

- `test/<case>/expected.json` — the harness compares the two engines to each
  other, not to a stored expectation, so regolibrary's own expected output is
  not the reference here.
- `test/<case>/data.json` — per-case `postureControlInputs` overrides. The Rego
  side reads `default-config-inputs.json` for every case instead, because that is
  what a scan reads; a case regolibrary wrote against a narrowed input may
  therefore fail where regolibrary's own test expects a pass. Both engines still
  see the configuration they would see in a scan, which is the question the
  harness is asking.

## What is changed, and why

Three mechanical edits to the fixtures. All are worth raising in regolibrary so a
later refresh does not undo them.

- **Removed API versions bumped to the served one.** Seven CronJob fixtures were
  on `batch/v1beta1` and one CSIStorageCapacity on `storage.k8s.io/v1beta1`. A
  VAP's `matchConstraints` name concrete versions where regolibrary's rule match
  uses `apiVersions: ["*"]`, so on the old version the fixture reached the Rego
  side and not the CEL side, and the case compared nothing at all. On `batch/v1`
  and `storage.k8s.io/v1` they compare, and they agree.
- **One renamed Service.** In
  `ensure-https-loadbalancers-encrypted-with-tls-aws/test/failed_multiple_loadbalancers`
  both fixtures were `Service/api` with no namespace, so they shared a resource
  ID and the second overwrote the first, leaving a case named for multiple load
  balancers testing one. The second is now `api-tls`. The harness refuses a case
  whose fixtures share an ID, so this cannot come back quietly.
- **One tab replaced with spaces**, in `role-in-default-namespace/test/role`. The
  reader the harness uses (`sigs.k8s.io/yaml`, over `go.yaml.in/yaml/v2`) accepts
  a tab used as separation before a comment, so the fixture parsed and the case
  ran either way. Stricter readers reject it, which makes the fixture a hazard
  for anything else that picks it up, so it is spaces now.

## Refreshing

```sh
git -C <regolibrary> archive <tag> | tar -x -C /tmp/regolib
cp /tmp/regolib/default-config-inputs.json .
# for each rule directory named in regoCELParityControls:
cp -r /tmp/regolib/rules/<rule-name> rules/
find rules -name expected.json -delete
find rules -name data.json -delete
```

Then update the tag at the top of this file and `regoCELParityLibraryVersion` in
the test, and run the harness. A control whose verdicts stop agreeing after a
refresh is the point of the exercise: either the Rego moved and the CEL policy
has to follow, or the divergence is deliberate and belongs on the `divergence`
list with a reason.
