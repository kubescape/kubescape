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
