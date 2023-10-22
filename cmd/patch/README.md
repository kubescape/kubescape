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

| Flag           | Description                                            | Required | Default                             |
| -------------- | ------------------------------------------------------ | -------- | ----------------------------------- |
| -i, --image    | Image name to be patched (should be in canonical form) | Yes      |                                     |
| -a, --addr     | Address of the buildkitd service                       | No       | unix:///run/buildkit/buildkitd.sock |
| -t, --tag      | Tag of the resultant patched image                     | No       | image_name-patched                  |
| --timeout      | Timeout for the patching process                       | No       | 5m                                  |
| -u, --username | Username for the image registry login                  | No       |                                     |
| -p, --password | Password for the image registry login                  | No       |                                     |
| -f, --format   | Output file format.                                    | No       |                                     |
| -o, --output   | Output file. Print output to file and not stdout       | No       |                                     |
| -v, --verbose  | Display full report. Default to false                  | No       |                                     |
| -h, --help     | help for patch                                         | No       |                                     |


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

3. You will get an output like below:

    ```bash
    ✅  Successfully scanned image: docker.io/library/nginx:1.22
    ✅  Patched image successfully. Loaded image: nginx:1.22-patched
    ✅  Successfully re-scanned image: nginx:1.22-patched

    | Severity | Vulnerability  | Component     | Version                 | Fixed In |
    | -------- | -------------- | ------------- | ----------------------- | -------- |
    | Critical | CVE-2023-23914 | curl          | 7.74.0-1.3+deb11u7      | wont-fix |
    | Critical | CVE-2019-8457  | libdb5.3      | 5.3.28+dfsg1-0.8        | wont-fix |
    | High     | CVE-2022-42916 | libcurl4      | 7.74.0-1.3+deb11u7      | wont-fix |
    | High     | CVE-2022-1304  | libext2fs2    | 1.46.2-2                | wont-fix |
    | High     | CVE-2022-42916 | curl          | 7.74.0-1.3+deb11u7      | wont-fix |
    | High     | CVE-2022-1304  | e2fsprogs     | 1.46.2-2                | wont-fix |
    | High     | CVE-2022-1304  | libcom-err2   | 1.46.2-2                | wont-fix |
    | High     | CVE-2023-27533 | curl          | 7.74.0-1.3+deb11u7      | wont-fix |
    | High     | CVE-2023-27534 | libcurl4      | 7.74.0-1.3+deb11u7      | wont-fix |
    | High     | CVE-2023-27533 | libcurl4      | 7.74.0-1.3+deb11u7      | wont-fix |
    | High     | CVE-2022-43551 | libcurl4      | 7.74.0-1.3+deb11u7      | wont-fix |
    | High     | CVE-2022-3715  | bash          | 5.1-2+deb11u1           | wont-fix |
    | High     | CVE-2023-27534 | curl          | 7.74.0-1.3+deb11u7      | wont-fix |
    | High     | CVE-2022-43551 | curl          | 7.74.0-1.3+deb11u7      | wont-fix |
    | High     | CVE-2021-33560 | libgcrypt20   | 1.8.7-6                 | wont-fix |
    | High     | CVE-2023-2953  | libldap-2.4-2 | 2.4.57+dfsg-3+deb11u1   | wont-fix |
    | High     | CVE-2022-1304  | libss2        | 1.46.2-2                | wont-fix |
    | High     | CVE-2020-22218 | libssh2-1     | 1.9.0-2                 | wont-fix |
    | High     | CVE-2023-29491 | libtinfo6     | 6.2+20201114-2+deb11u1  | wont-fix |
    | High     | CVE-2022-2309  | libxml2       | 2.9.10+dfsg-6.7+deb11u4 | wont-fix |
    | High     | CVE-2022-4899  | libzstd1      | 1.4.8+dfsg-2.1          | wont-fix |
    | High     | CVE-2022-1304  | logsave       | 1.46.2-2                | wont-fix |
    | High     | CVE-2023-29491 | ncurses-base  | 6.2+20201114-2+deb11u1  | wont-fix |
    | High     | CVE-2023-29491 | ncurses-bin   | 6.2+20201114-2+deb11u1  | wont-fix |
    | High     | CVE-2023-31484 | perl-base     | 5.32.1-4+deb11u2        | wont-fix |
    | High     | CVE-2020-16156 | perl-base     | 5.32.1-4+deb11u2        | wont-fix |
    
    Vulnerability summary - 161 vulnerabilities found:
    Image: nginx:1.22-patched
      * 3 Critical
      * 24 High
      * 31 Medium
      * 103 Other

    Most vulnerable components:
      * curl (7.74.0-1.3+deb11u7) - 1 Critical, 4 High, 5 Medium, 1 Low, 3 Negligible
      * libcurl4 (7.74.0-1.3+deb11u7) - 1 Critical, 4 High, 5 Medium, 1 Low, 3 Negligible
      * libtiff5 (4.2.0-1+deb11u4) - 7 Medium, 10 Negligible, 2 Unknown
      * libxml2 (2.9.10+dfsg-6.7+deb11u4) - 1 High, 2 Medium
      * perl-base (5.32.1-4+deb11u2) - 2 High, 2 Negligible
    
    What now?
    ─────────
    * Run with '--verbose'/'-v' flag for detailed vulnerabilities view
    * Install Kubescape in your cluster for continuous monitoring and a full vulnerability report: https://github.com/kubescape/helm-charts/tree/main/charts/kubescape-cloud-operator
    ```

## Limitations

- The patch command can only fix OS-level vulnerability. It cannot fix application-level vulnerabilities. This is a limitation of copa. The reason behind this is that application level vulnerabilities are best suited to be fixed by the developers of the application.
Hence, this is not really a limitation but a design decision.
- No support for windows containers given the dependency on buildkit.
