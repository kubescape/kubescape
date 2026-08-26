# In-tree policy rules

This directory is a development and validation area for policy rules that are
maintained alongside Kubescape. It is not a policy source for normal scans.
Kubescape obtains the controls and frameworks used by default scans from the
[regolibrary](https://github.com/kubescape/regolibrary), so merging a rule here
does not publish it to users.

## Test the fixtures

Each rule directory contains `raw.rego`, `rule.metadata.json`, and test cases
under `test/<case>/`. A test case has Kubernetes manifests in `input/` and the
expected rule responses in `expected.json`.

Run all in-tree fixtures with:

```sh
go run . policy test ./rules
```

To iterate on one rule, pass its directory instead:

```sh
go run . policy test ./rules/<rule-name>
```

The Go test suite runs the full-directory command, so a pull request fails CI
when an in-tree rule no longer matches its fixtures.

## Publish a rule

To make an in-tree rule available to default scans:

1. Keep its Rego, metadata, and fixtures passing in this repository.
2. Add or update the corresponding `rules/<rule-name>` directory in
   [kubescape/regolibrary](https://github.com/kubescape/regolibrary).
3. In regolibrary, associate the rule with a control through the control's
   `rulesNames` field and include that control in any intended frameworks.
4. Run regolibrary's rule tests and follow its review and release process.

The rule becomes part of Kubescape's default policy data only after the
regolibrary change is merged and published.
