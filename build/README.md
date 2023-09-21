## Docker Build

### Build your own Docker image

1. Clone Project
```
git clone https://github.com/kubescape/kubescape.git kubescape && cd "$_"
```

2. Build kubescape CLI Docker image
```
make all
docker buildx build -t kubescape-cli -f build/kubescape-cli.Dockerfile --build-arg="ks_binary=kubescape" --load .
```

3. Build kubescape Docker image
```
docker buildx build -t kubescape -f build/Dockerfile --load .
```
