# vapdata

Vendored copy of the [cel-admission-library](https://github.com/kubescape/cel-admission-library)
release bundle. The CEL engine embeds these files with `//go:embed` so the
policies are baked into the binary and there are no runtime file-path issues.

Do not edit these files by hand. They are a verbatim copy of a pinned release
(see `CEL_LIBRARY_VERSION` in the Makefile) and are refreshed with:

```sh
make sync-vap
```

Files:

- `kubescape-validating-admission-policies.yaml` — the ValidatingAdmissionPolicy
  documents (one per control, `---` separated). This is what the loader parses
  and hands to the evaluator.
- `basic-control-configuration.yaml` — the parameter values a policy's
  `paramKind` resolves against.
- `policy-configuration-definition.yaml` — the parameter CRD definition that
  backs those params.

## Local deviations from the pinned release

The bundle is normally byte-identical to the release named by
`CEL_LIBRARY_VERSION`. It currently is not: three policies in `v0.12` set
`message` to a CEL string concatenation instead of `messageExpression`. Only
`messageExpression` is evaluated - `message` is emitted verbatim - so a
violation on any of them showed the literal, unevaluated expression instead
of a message naming the resource.

Patched here, ahead of a release that carries the fix:

- **C-0013**, **C-0198**, **C-0210** — `message` holds what should be a
  `messageExpression`. Fix sent upstream, not yet merged:
  kubescape/cel-admission-library#100.

`make sync-vap` overwrites these edits. When a release carrying the fix is
available, bump `CEL_LIBRARY_VERSION`, re-sync, and delete this section
rather than re-applying the patch by hand.
`TestNoStaticMessageIsACELExpression` in `../messageexpression_test.go` fails
if a re-sync drops it.

A submodule was considered instead of a vendored copy, but `//go:embed` only
picks up files committed in this repo, and a submodule's contents are dropped
when kubescape is pulled in as a Go module (the embed then fails with
"no matching files found"). A vendored copy always travels with the module.
