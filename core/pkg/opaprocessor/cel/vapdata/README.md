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
`CEL_LIBRARY_VERSION`. It currently is not: three policies in `v0.11` walk
optional fields without a `has()` guard, which is harmless at live admission
(the object there is schema-defaulted) but makes the offline engine eval-error
and report ordinary workloads as `Skipped/Unknown` instead of evaluating them.

Patched here, ahead of a release that carries the fix:

- **C-0045** — all three validations read `spec.volumes` unguarded, so every
  workload without a `volumes` block was skipped. Fixed upstream on `main`.
- **C-0048** — the CronJob validation guarded
  `spec.jobTemplate.spec.volumes` but read
  `spec.jobTemplate.spec.template.spec.volumes`; the guarded path never exists,
  so the expression always short-circuited and a hostPath CronJob passed
  silently. Fixed upstream on `main`.
- **C-0055** — the Workload and CronJob validations walk into the optional
  `template.metadata` unguarded (`has(a.b.c)` does not guard a missing `a.b`),
  and the CronJob validation read `securityContext` from
  `spec.jobTemplate.spec` rather than the pod template. The path fix is
  upstream on `main`; the `metadata` guard is not, and needs a fix there.

`make sync-vap` overwrites these edits. When a release past `v0.11` is
available, bump `CEL_LIBRARY_VERSION`, re-sync, and delete this section rather
than re-applying the patches by hand. `TestNoEvalErrorOnMinimalWorkloads` in
`../optionalfields_test.go` fails if a re-sync drops any of them.

A submodule was considered instead of a vendored copy, but `//go:embed` only
picks up files committed in this repo, and a submodule's contents are dropped
when kubescape is pulled in as a Go module (the embed then fails with
"no matching files found"). A vendored copy always travels with the module.
