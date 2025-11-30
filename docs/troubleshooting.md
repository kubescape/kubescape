# Troubleshooting Guide

This guide covers common issues you may encounter when using Kubescape and how to resolve them.

## Table of Contents

- [Installation Issues](#installation-issues)
- [Scanning Issues](#scanning-issues)
- [Image Scanning Issues](#image-scanning-issues)
- [Image Patching Issues](#image-patching-issues)
- [Operator Issues](#operator-issues)
- [MCP Server Issues](#mcp-server-issues)
- [Output and Reporting Issues](#output-and-reporting-issues)
- [Performance Issues](#performance-issues)
- [Getting Help](#getting-help)

---

## Installation Issues

### Command not found after installation

**Symptom:** After running the install script, `kubescape` command is not found.

**Solution:**

1. Check if the binary was installed:
   ```bash
   ls -la ~/.kubescape/kubescape
   ```

2. Add to your PATH:
   ```bash
   # For bash
   echo 'export PATH=$PATH:~/.kubescape' >> ~/.bashrc
   source ~/.bashrc

   # For zsh
   echo 'export PATH=$PATH:~/.kubescape' >> ~/.zshrc
   source ~/.zshrc
   ```

3. Alternatively, move the binary to a directory already in your PATH:
   ```bash
   sudo mv ~/.kubescape/kubescape /usr/local/bin/
   ```

### Permission denied during installation

**Symptom:** Installation fails with permission errors.

**Solution:**

```bash
# Create the directory with proper permissions
mkdir -p ~/.kubescape
chmod 755 ~/.kubescape

# Re-run the installation
curl -s https://raw.githubusercontent.com/kubescape/kubescape/master/install.sh | /bin/bash
```

### Installation fails on Windows

**Symptom:** PowerShell script fails to execute.

**Solution:**

1. Check PowerShell version (must be v5.0+):
   ```powershell
   $PSVersionTable.PSVersion
   ```

2. Set execution policy:
   ```powershell
   Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
   ```

3. Retry installation:
   ```powershell
   iwr -useb https://raw.githubusercontent.com/kubescape/kubescape/master/install.ps1 | iex
   ```

---

## Scanning Issues

### Cannot connect to cluster

**Symptom:** `kubescape scan` fails with connection errors.

**Solutions:**

1. Verify kubectl works:
   ```bash
   kubectl get nodes
   ```

2. Check your kubeconfig:
   ```bash
   kubectl config current-context
   kubectl config view
   ```

3. Use an explicit kubeconfig:
   ```bash
   kubescape scan --kubeconfig /path/to/kubeconfig
   ```

4. Use a specific context:
   ```bash
   kubescape scan --kube-context my-context
   ```

### Scan times out

**Symptom:** Scanning large clusters takes too long or times out.

**Solutions:**

1. Scan specific namespaces:
   ```bash
   kubescape scan --include-namespaces production,staging
   ```

2. Exclude non-essential namespaces:
   ```bash
   kubescape scan --exclude-namespaces kube-system,kube-public,monitoring
   ```

3. Scan a specific framework instead of all:
   ```bash
   kubescape scan framework nsa
   ```

### No results returned

**Symptom:** Scan completes but shows no results.

**Solutions:**

1. Check if the cluster has workloads:
   ```bash
   kubectl get pods --all-namespaces
   ```

2. Run with verbose output:
   ```bash
   kubescape scan -v
   ```

3. Check for namespace filtering issues:
   ```bash
   # Make sure you're not excluding all namespaces
   kubescape scan --include-namespaces default
   ```

### Framework or control not found

**Symptom:** Error about unknown framework or control.

**Solutions:**

1. List available frameworks:
   ```bash
   kubescape list frameworks
   ```

2. List available controls:
   ```bash
   kubescape list controls
   ```

3. Update Kubescape to get latest controls:
   ```bash
   # Re-run installation to get latest version
   curl -s https://raw.githubusercontent.com/kubescape/kubescape/master/install.sh | /bin/bash
   ```

4. Download latest artifacts:
   ```bash
   kubescape download artifacts
   ```

### RBAC errors during scan

**Symptom:** Scan fails with permission denied errors.

**Solution:**

Ensure your kubeconfig user has sufficient permissions. At minimum, you need read access to:
- Deployments, DaemonSets, StatefulSets, Jobs, CronJobs
- Pods, Services, ConfigMaps, Secrets
- Roles, RoleBindings, ClusterRoles, ClusterRoleBindings
- NetworkPolicies
- ServiceAccounts

---

## Image Scanning Issues

### Image not found

**Symptom:** `kubescape scan image` fails to find the image.

**Solutions:**

1. Use the full image reference:
   ```bash
   kubescape scan image docker.io/library/nginx:1.21
   ```

2. For private registries, provide credentials:
   ```bash
   kubescape scan image myregistry.io/myimage:tag \
     --username myuser \
     --password mypassword
   ```

3. Check if the image exists locally:
   ```bash
   docker images | grep myimage
   ```

### Authentication failed for private registry

**Symptom:** Scan fails with authentication errors.

**Solutions:**

1. Verify credentials work with docker:
   ```bash
   docker login myregistry.io
   docker pull myregistry.io/myimage:tag
   ```

2. Use environment variables for credentials:
   ```bash
   export KUBESCAPE_REGISTRY_USERNAME=myuser
   export KUBESCAPE_REGISTRY_PASSWORD=mypassword
   kubescape scan image myregistry.io/myimage:tag
   ```

### Vulnerability database outdated

**Symptom:** Known CVEs are not being detected.

**Solution:**

The vulnerability database is updated automatically. To force an update:

```bash
# Clear the cache
rm -rf ~/.kubescape/grype-db

# Run a new scan
kubescape scan image nginx:latest
```

---

## Image Patching Issues

### BuildKit not running

**Symptom:** `kubescape patch` fails with BuildKit connection errors.

**Solutions:**

1. Start BuildKit:
   ```bash
   sudo buildkitd &
   ```

2. Or run BuildKit in Docker:
   ```bash
   docker run --detach --rm --privileged \
     -p 127.0.0.1:8888:8888/tcp \
     --name buildkitd \
     --entrypoint buildkitd \
     moby/buildkit:latest \
     --addr tcp://0.0.0.0:8888

   kubescape patch -i nginx:1.22 -a tcp://0.0.0.0:8888
   ```

3. Check BuildKit socket:
   ```bash
   ls -la /run/buildkit/buildkitd.sock
   ```

### Patching fails with no fixes available

**Symptom:** Patch command reports no patches available.

**Explanation:** Image patching only fixes OS-level vulnerabilities that have available patches. Application-level vulnerabilities or vulnerabilities without fixes cannot be patched.

**Solution:**

1. Check the vulnerability report:
   ```bash
   kubescape scan image myimage:tag -v
   ```

2. Look for vulnerabilities marked as "wont-fix" or without fix versions.

3. Consider updating the base image to a newer version.

### Permission denied during patching

**Symptom:** Patch fails with permission errors.

**Solution:**

Run with sudo when using the default Unix socket:
```bash
sudo kubescape patch --image nginx:1.22
```

Or use the Docker-based BuildKit approach which doesn't require sudo.

---

## Operator Issues

### Operator not responding to CLI commands

**Symptom:** `kubescape operator scan` hangs or fails.

**Solutions:**

1. Verify the operator is installed:
   ```bash
   kubectl -n kubescape get pods
   ```

2. Check operator logs:
   ```bash
   kubectl -n kubescape logs -l app=kubescape-operator
   ```

3. Verify the operator service:
   ```bash
   kubectl -n kubescape get svc
   ```

### No vulnerability manifests in cluster

**Symptom:** No VulnerabilityManifest CRs found.

**Solutions:**

1. Check if vulnerability scanning is enabled:
   ```bash
   kubectl -n kubescape get configmap kubescape-config -o yaml
   ```

2. Verify kubevuln is running:
   ```bash
   kubectl -n kubescape get pods -l app=kubevuln
   ```

3. Check kubevuln logs:
   ```bash
   kubectl -n kubescape logs -l app=kubevuln
   ```

---

## MCP Server Issues

### MCP server fails to start

**Symptom:** `kubescape mcpserver` exits with errors.

**Solutions:**

1. Verify kubectl connectivity:
   ```bash
   kubectl get nodes
   ```

2. Check if the operator CRDs are installed:
   ```bash
   kubectl get crd vulnerabilitymanifests.spdx.softwarecomposition.kubescape.io
   kubectl get crd workloadconfigurationscans.spdx.softwarecomposition.kubescape.io
   ```

3. Install the Kubescape operator if not present:
   ```bash
   helm repo add kubescape https://kubescape.github.io/helm-charts/
   helm upgrade --install kubescape kubescape/kubescape-operator \
     --namespace kubescape --create-namespace
   ```

### AI assistant cannot connect to MCP server

**Symptom:** AI tool reports connection failures.

**Solutions:**

1. Verify the MCP server is running:
   ```bash
   kubescape mcpserver
   ```

2. Check your AI tool's MCP configuration:
   ```json
   {
     "mcpServers": {
       "kubescape": {
         "command": "kubescape",
         "args": ["mcpserver"]
       }
     }
   }
   ```

3. Ensure kubescape is in your PATH.

---

## Output and Reporting Issues

### JSON output is malformed

**Symptom:** JSON output cannot be parsed.

**Solution:**

Ensure you're redirecting to a file, not mixing with console output:
```bash
kubescape scan --format json --output results.json
```

### SARIF format fails

**Symptom:** SARIF output not working.

**Note:** SARIF format is only supported for file/repository scans, not live cluster scans.

**Solution:**
```bash
# This works
kubescape scan /path/to/manifests --format sarif --output results.sarif

# This does NOT work
kubescape scan --format sarif --output results.sarif  # cluster scan
```

### HTML/PDF report generation fails

**Symptom:** Report generation fails or produces empty files.

**Solutions:**

1. Ensure you have write permissions to the output directory.

2. Check available disk space.

3. Try JSON first to verify scan works:
   ```bash
   kubescape scan --format json --output test.json
   ```

---

## Performance Issues

### High memory usage during scan

**Solutions:**

1. Scan fewer namespaces:
   ```bash
   kubescape scan --include-namespaces production
   ```

2. Scan one framework at a time:
   ```bash
   kubescape scan framework nsa
   ```

3. Use the operator for large clusters instead of CLI scanning.

### Slow vulnerability database downloads

**Solutions:**

1. Use offline mode with pre-downloaded artifacts:
   ```bash
   # On a machine with good connectivity
   kubescape download artifacts --output /path/to/artifacts

   # On the target machine
   kubescape scan --use-artifacts-from /path/to/artifacts
   ```

2. Configure a proxy if needed:
   ```bash
   export HTTPS_PROXY=http://proxy:8080
   kubescape scan
   ```

---

## Getting Help

If you're still experiencing issues:

1. **Check the logs** with debug logging:
   ```bash
   kubescape scan -l debug
   ```

2. **Search existing issues:**
   https://github.com/kubescape/kubescape/issues

3. **Join the community Slack:**
   - [Users Channel](https://cloud-native.slack.com/archives/C04EY3ZF9GE)
   - [Developers Channel](https://cloud-native.slack.com/archives/C04GY6H082K)

4. **Open a new issue** with:
   - Kubescape version (`kubescape version`)
   - Kubernetes version (`kubectl version`)
   - Full error message
   - Steps to reproduce
   - Debug logs (`kubescape scan -l debug 2>&1 | tee debug.log`)