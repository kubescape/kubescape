# Building Kubescape

## Build on Windows

1. Install MSYS2 & build libgit _(needed only for the first time)_

    ```
    build.bat all
    ```

> **Note**  
> You can install MSYS2 separately by running `build.bat install` and build libgit2 separately by running `build.bat build`

2. Build kubescape

    ```
    make build
    ```

    OR 

    ```
    go build -tags=static .
    ```


## Build on Linux/MacOS

1. Install libgit2 dependency _(needed only for the first time)_
   
    ```
    make libgit2
    ```

> **Note**  
> `cmake` is required to build libgit2. You can install it by running `sudo apt-get install cmake` (Linux) or `brew install cmake` (macOS).

2. Build kubescape

    ```
    make build
    ```

    OR 

    ```
    go build -tags=static .
    ```

3. Test

    ```
    make test
    ```

## Build Kubescape in a pre-configured playground

We have created a [Killercoda scenario](https://killercoda.com/suhas-gumma/scenario/kubescape-build-for-development) that you can use to experiment building Kubescape from source.

When you start the scenario, a script will clone the Kubescape repository and [execute a Linux build steps](https://github.com/kubescape/kubescape#build-on-linuxmacos).  The entire process executes multiple commands in order: it takes around 5-6 minutes to complete.

How to use the build playground:

* Apply changes you wish to make to the Kubescape source code. 
* [Perform a Linux build](#build-on-linuxmacos)
* Now, you can use Kubescape like normal, but instead of using `kubescape`, use `./kubescape`.

## VS Code configuration samples

You can use the sample files below to setup your VS Code environment for building and debugging purposes.

`.vscode/settings.json`:

```json5
// .vscode/settings.json
{
    "go.testTags": "static",
    "go.buildTags": "static",
    "go.toolsEnvVars": {
        "CGO_ENABLED": "1"
    }
}
```

`.vscode/launch.json`:

```json5
// .vscode/launch.json
{
    "version": "0.2.0",
    "configurations": [
        {
            "name": "Launch Package",
            "type": "go",
            "request": "launch",
            "mode": "auto",
            "program": "${workspaceFolder}/main.go",
            "args": [
                "scan",
                "--logger",
                "debug"
            ],
            "buildFlags": "-tags=static"
        }
    ]
}
```
