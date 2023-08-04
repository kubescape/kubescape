# Patch Command

The patch command is used for patching container images with vulnerabilities.  
It uses [copa](https://github.com/project-copacetic/copacetic) and [buildkit](https://github.com/moby/buildkit) under the hood for patching the container images, and [grype](https://github.com/anchore/grype) as the engine for scanning the images (at the moment).

## Usage

```bash
kubescape patch --image <image-name> [flags]
```

The patch command can be run in 2 ways:
1. **With sudo privileges**

    You will need to start `buildkitd` if it is not already running

    ```bash
    sudo buildkitd & 
    sudo kubescape patch --image <image-name>
    ```

2. **Without sudo privileges**
   ```bash
    export BUILDKIT_VERSION=v0.11.4
    export BUILDKIT_PORT=8888

    docker run \
        --detach \
        --rm \
        --privileged \
        -p 127.0.0.1:$BUILDKIT_PORT:$BUILDKIT_PORT/tcp \
        --name buildkitd \
        --entrypoint buildkitd \
        "moby/buildkit:$BUILDKIT_VERSION" \
        --addr tcp://0.0.0.0:$BUILDKIT_PORT

    kubescape patch \
        -i <image-name> \
        -a tcp://0.0.0.0:$BUILDKIT_PORT
   ```

### Flags

| Flag | Description | Required | Default |
|------|-------------|----------|---------|
| -i, --image | Image name to be patched (should be in canonical form) | Yes | |
| -r, --report | Generate reports of the image scan before and after patching | No | false | 
| -a, --addr | Address of the buildkitd service | No | unix:///run/buildkit/buildkitd.sock |
| -t, --tag | Tag of the resultant patched image | No | image_name-patched |
| --timeout | Timeout for the patching process | No | 5m |
| -u, --username | Username for the image registry login | No | |
| -p, --password | Password for the image registry login | No | |
| -h, --help | help for patch | No | |


## Example

We will demonstrate how to use the patch command with an example of [nginx](https://www.nginx.com/) image.

### Pre-requisites

- [docker](https://docs.docker.com/desktop/install/linux-install/#generic-installation-steps) daemon must be installed and running.
- [buildkit](https://github.com/moby/buildkit) daemon must be installed
    
### Steps

1. Run `buildkitd` service:

    ```bash
    sudo buildkitd
    ```

2. In a seperate terminal, run the `kubescape patch` command: 
    
    ```bash
    sudo kubescape patch --image docker.io/library/nginx:1.22
    ```

3. The output will be similar to:

    ```bash
    [info] Scanning image...
    [success] Scanned image successfully
    [info] Patching image...
    ...<logs>
    [success] Patched image successfully
    [info] Re-scanning image...
    [success] Re-scanned image successfully
    [info] Preparing results ...
    
    Vulnerability summary:
    Image: docker.io/library/nginx:1.22
      * Total CVE's  : 175
      * Fixable CVE's: 23

    Image: docker.io/library/nginx:1.22-patched
       * Total CVE's  : 152
       * Fixable CVE's: 0

    ```

## Limitations

- The patch command can only fix OS-level vulnerability. It cannot fix application-level vulnerabilities. This is a limitation of copa. The reason behind this is that application level vulnerabilities are best suited to be fixed by the developers of the application.
Hence, this is not really a limitation but a design decision.
- No support for windows containers given the dependency on buildkit.
