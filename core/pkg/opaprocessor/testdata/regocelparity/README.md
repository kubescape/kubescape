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

Then per rule, mirroring regolibrary so a refresh is a plain copy:

```
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
