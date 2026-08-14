# List command CSV output

Kubescape now supports CSV output for the list command so framework, exception, and control data can be imported into spreadsheets and automation pipelines more easily.

## Supported formats

The list command already supports `pretty-print`, `json`, and `yaml`. It now also accepts `csv`.

## Examples

### Frameworks as CSV

```bash
kubescape list frameworks --format csv
```

Example output:

```csv
name
nsa
mitre
```

### Controls as CSV

```bash
kubescape list controls --format csv
```

Example output:

```csv
id,name,frameworks
C-0001,Forbidden Registries,NSA;MITRE
C-0002,Privileged Containers,AllControls
```

## Why this helps

CSV output makes it easier to:

- open policy lists in Excel or Google Sheets
- feed results into downstream automation scripts
- compare control inventories across environments
- archive inventory data in a simple, portable format
