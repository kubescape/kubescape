# vapdata

Vendored copy of the [cel-admission-library](https://github.com/kubescape/cel-admission-library)
release bundle. The CEL engine embeds these files with `//go:embed` so the
policies are baked into the binary and there are no runtime file-path issues.

Do not edit these files by hand. They are a verbatim copy of the latest release
and are refreshed with:

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

A submodule was considered instead of a vendored copy, but `//go:embed` only
picks up files committed in this repo, and a submodule's contents are dropped
when kubescape is pulled in as a Go module (the embed then fails with
"no matching files found"). A vendored copy always travels with the module.
