# Config output rendering

Kubescape can now render cached configuration values in multiple output formats so operators can inspect the active configuration in the format that best fits their workflow.

## Why this matters

The configuration view command previously printed the cached JSON payload directly. That worked for machine-oriented use cases, but it was harder to inspect interactively when you wanted a quick summary or a YAML-friendly representation.

The new output support adds:

- human-readable text output for terminal use
- JSON output for automation and scripts
- YAML output for environments that already consume YAML manifests
- an optional flag to include empty values when you need a more complete schema-like view

## Supported formats

The command accepts the following values with the `--output` flag:

- `text` (default): a compact, human-readable block of `key: value` entries
- `json`: a JSON object with the current config fields
- `yaml`: a YAML mapping with the current config fields

## Examples

### Default text output

```bash
kubescape config view
```

Example output:

```text
accountID: 1234567890
cloudAPIURL: https://api.example.com
cloudReportURL: https://report.example.com
```

### JSON output

```bash
kubescape config view -o json
```

Example output:

```json
{
  "accountID": "1234567890",
  "cloudAPIURL": "https://api.example.com",
  "cloudReportURL": "https://report.example.com"
}
```

### YAML output

```bash
kubescape config view -o yaml
```

Example output:

```yaml
accountID: 1234567890
cloudAPIURL: https://api.example.com
cloudReportURL: https://report.example.com
```

### Include empty values

If you want the output to preserve the full field structure, including empty values, use the `--include-empty` flag.

```bash
kubescape config view -o json --include-empty
```

Example output:

```json
{
  "accessKey": "",
  "accountID": "1234567890",
  "clusterName": "",
  "cloudAPIURL": "https://api.example.com",
  "cloudReportURL": "https://report.example.com"
}
```

## Command reference

```bash
kubescape config view [--output text|json|yaml] [--include-empty]
```

### Flags

- `-o, --output`: select the rendering format
- `-e, --include-empty`: include empty values in the rendered payload

## Integration notes

This output formatting is helpful when you want to:

1. inspect the current cached configuration locally
2. pipe the result into another tool or script
3. compare a local cached configuration with a generated YAML or JSON payload
4. debug configuration drift between environments

## Output contract

The rendered fields use stable lower camel case names:

- `accountID`
- `clusterName`
- `cloudReportURL`
- `cloudAPIURL`
- `accessKey`

`accessKey` is a credential, so it is rendered masked in every format: only its
last four characters are shown, prefixed with `****` (a key of eight characters
or fewer is masked in full). The command is meant for CI logs and shared
terminals, so it never prints the key itself; read the cached configuration file
directly if you need the full value.

By default, fields with empty values are not rendered. This keeps terminal
output short and avoids noisy structured payloads in scripts that only need
configured values.

When `--include-empty` is set, every supported field is rendered even if its
value is empty. This is useful for tools that validate the expected shape of
the cached configuration.

The `text` format renders one `key: value` pair per line. It is designed for
operators reading logs or terminals, not for strict machine parsing.

The `json` format renders a JSON object. Scripts can read the fields with tools
such as `jq` without depending on the text layout.

The `yaml` format renders a YAML mapping. This is convenient when comparing the
cached values with Kubernetes manifests, Helm values, or other YAML-oriented
configuration files.

Unknown output formats return an error instead of falling back to text. This
helps automation fail early when a flag value is misspelled.

The command only reads and renders the cached configuration. It does not create,
update, delete, or normalize the saved configuration file.

### Scripting guidance

For scripts, prefer `-o json` and check for missing keys explicitly.

For reviews, prefer `-o yaml --include-empty` so unset fields are visible.

For logs, prefer the default text format because it is compact.

Do not treat omitted fields as deleted configuration values.

Quote shell variables that may contain URLs or access keys.

## Use cases

### Troubleshooting a missing account ID

When an account ID appears to be missing, you can render the config in a structured format and compare the values across environments.

```bash
kubescape config view -o yaml
```

### Preparing automation snippets

You can use JSON output to build scripts that validate that required configuration keys are present before a scan starts.

```bash
kubescape config view -o json | jq '.accountID'
```

### Reviewing configuration changes

The text output is ideal for quick human inspection in CI logs or local development shells.

```bash
kubescape config view
```

## Notes

- The default output remains compact and easy to read in the terminal.
- Empty values are omitted unless `--include-empty` is specified.
- The command does not modify your cached configuration; it only renders the current state.

## Example walkthrough

A common workflow looks like this:

```bash
kubescape config view -o json
kubescape config set accountID <your-account-id>
kubescape config view -o yaml
```

This sequence lets you verify the current configuration, update it, and then render the result in a structure that is easier to reason about.

## Summary

The enhanced configuration view output gives you more flexibility without changing the underlying cached configuration model. Whether you prefer a terminal-friendly text layout or structured JSON or YAML, the command now supports your preferred workflow.
