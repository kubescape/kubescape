## Docker Build

### Build your own Docker image

1. Clone Project
```
git clone https://github.com/kubescape/kubescape.git kubescape && cd "$_"
```

2. Build
```
docker build -t kubescape -f build/Dockerfile .
```