# Image Scanning

Kubescape provides a powerful command-line interface to scan container images for vulnerabilities. This guide explains how to use the `scan image` command effectively.

## Basic Usage

To scan a single container image, use the `scan image` command followed by the image name:

```bash
kubescape scan image "nginx"
```

You can also specify a specific tag:

```bash
kubescape scan image "nginx:1.27"
```

## Advanced Usage

### Scanning Multiple Images

You can scan multiple images in a single run. This is more efficient as it shares a single vulnerability database load across all images.

```bash
kubescape scan image "nginx:1.27" "redis:7" "postgres:16"
```

### Concurrency

By default, Kubescape scans images sequentially. You can speed up the process by using concurrent workers when scanning multiple images.

```bash
kubescape scan image "nginx:1.27" "redis:7" --image-scan-concurrency 4
```

### Verbose Output

To see the full vulnerability report, use the `-v` (verbose) flag:

```bash
kubescape scan image "nginx" -v
```

### Exploitability: KEV and EPSS

The vulnerability table in the pretty, HTML, Markdown and PDF outputs has two
columns that show how likely each vulnerability is to be exploited:

- `KEV` is `yes` when the vulnerability is on the CISA
  [Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
  catalog, meaning it has been exploited in the wild.
- `EPSS` is the [Exploit Prediction Scoring System](https://www.first.org/epss/)
  probability of exploitation in the next 30 days, followed by its percentile,
  for example `63.9% (99th)`. It is `N/A` when the vulnerability has no score.
  The PDF shows the probability only.

Rows are sorted with KEV entries first, then by severity, then by EPSS score.
The default (non-verbose) table, which otherwise lists only Critical and High
vulnerabilities, always includes KEV entries whatever their severity, and the
summary counts them.

Both values come from the Grype vulnerability database, including the offline
database image. EPSS scores change daily, so their accuracy depends on how
recently the database was built (see `--max-db-age`).

### Exceptions

If you want to ignore certain vulnerabilities based on an exceptions file, use the `--exceptions` flag:

```bash
kubescape scan image "nginx" --exceptions exceptions.json
```

### Multi-Architecture Images

When scanning multi-architecture images, you can specify the target platform (e.g., `linux/amd64`, `linux/arm64/v8`) using the `--platform` flag:

```bash
kubescape scan image "nginx" --platform linux/amd64
```

For more details on scanning images built for multiple architectures, please see the [Multi-Architecture Image Scanning guide](multi-architecture-image-scanning.md).

## Further Reading

For a complete list of flags and options available for the `scan image` command, refer to the [CLI Reference](cli-reference.md).
