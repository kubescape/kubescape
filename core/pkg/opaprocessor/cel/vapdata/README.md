# vapdata

Vendored copy of the [cel-admission-library](https://github.com/kubescape/cel-admission-library)
release bundle. The CEL engine embeds these files with `//go:embed` so the
policies are baked into the binary and there are no runtime file-path issues.

Do not edit these files by hand. They are a verbatim copy of a pinned release
(see `CEL_LIBRARY_VERSION` in the Makefile) and are refreshed with:

```sh
make sync-vap
```

Because these files are compiled into the binary, `sync-vap` verifies every
download against the SHA256 digests pinned in `CEL_VAP_DIGESTS` (the upstream
release publishes no checksum manifest of its own) and refuses to install a
bundle that does not match, so a tampered release asset cannot silently change
the policies kubescape enforces. Nothing is written unless every file verifies.

To move to a new release, bump `CEL_LIBRARY_VERSION`, then regenerate the
digests and check them against the upstream release before committing both
changes together:

```sh
make sync-vap-digests
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
