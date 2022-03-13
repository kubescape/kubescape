# Kubescape core package

```go

// initialize kubescape
ks := core.NewKubescape()

// scan cluster
results, err := ks.Scan(&cautils.ScanInfo{})

// convert scan results to json
jsonRes, err := results.ToJson()

```