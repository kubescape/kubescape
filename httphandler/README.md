# Kubescape HTTP Handler Package

Running `kubescape` will start up a web-server on port `8080` which will serve the following API's: 

### Trigger scan

* POST `/v1/scan` - triggers a Kubescape scan. The server will return an ID and will execute the scanning asynchronously. The request body should look [as follows](#trigger-scan-object).
* * `wait=true`: scan synchronously (return results and not ID). Use only in small clusters or with an increased timeout. Default is `wait=false`
* * `keep=true`: do not delete results from local storage after returning. Default is `keep=false`

[Response](#response-object):

```
{
  "id": <str>,                      // scan ID
  "type": "busy",                   // response object type
  "response": <message:string>      // message indicating scanning is still in progress
}
```

> When scanning was triggered with the `wait=true` query param, the response is like the [`/v1/results` API](#get-results) response

### Get results
* GET `/v1/results` -  request kubescape scan results
* * query `id=<string>` -> request results of a specific scan ID. If empty will return the latest results
* * query `keep=true` -> keep the results in the local storage after returning. default is `keep=false` - the results will be deleted from local storage after they are returned

[Response](#response-object):

When scanning was done successfully
```
{
  "id": <str>,                      // scan ID
  "type": "v1results",              // response object type
  "response": <object:v1results>    // v1 results payload
}
```

When scanning failed
```
{
  "id": <str>,                  // scan ID
  "type": "error",              // response object type
  "response": <error:string>    // error string
}
```

When scanning is in progress
```
{
  "id": <str>,                    // scan ID
  "type": "busy",                 // response object type
  "response": <message:string>    // message indicating scanning is still in progress
}
```
### Check scanning progress status
Check the scanning status - is the scanning in progress or done. This is meant for a waiting mechanize since the API does not return the entire results object when the scanning is done

* GET `/v1/status` -  Request kubescape scan status
* * query `id=<string>` -> Check status of a specific scan. If empty, it will check if any scan is still in progress

[Response](#response-object):

When scanning is in progress
```
{
  "id": <str>,                    // scan ID
  "type": "busy",                 // response object type
  "response": <message:string>    // message indicating scanning is still in process
}
```

When scanning is not in progress
```
{
  "id": <str>,                    // scan ID
  "type": "notBusy",              // response object type
  "response": <message:string>    // message indicating scanning is successfully done
}
```

### Delete cached results
* DELETE `/v1/results` - Delete kubescape scan results from storage. If empty will delete the latest results
* * query `id=<string>`: Delete ID of specific results 
* * query `all`: Delete all cached results

## Objects

### Trigger scan object

```
{
  "format": <str>,               // results format [default: json] (same as 'kubescape scan --format')
  "excludedNamespaces": [<str>], // list of namespaces to exclude (same as 'kubescape scan --excluded-namespaces')
  "includeNamespaces": [<str>],  // list of namespaces to include (same as 'kubescape scan --include-namespaces')
  "useCachedArtifacts"`: <bool>, // use the cached artifacts instead of downloading (offline support)
  "hostScanner": <bool>,         // deploy Kubescape host-sensor daemonset in the scanned cluster. Deleting it right after we collecting the data. Required to collect valuable data from cluster nodes for certain controls
  "keepLocal": <bool>,           // do not submit results to Kubescape cloud (same as 'kubescape scan --keep-local')
  "account": <str>,              // account ID (same as 'kubescape scan --account')
  "access-key": <str>,            // account ID (same as 'kubescape scan --accessKey')
  "targetType": <str>,           // framework/control
  "targetNames": [<str>]         // names. e.g. when targetType==framework, targetNames=["nsa", "mitre"]
}
```

### Response object

```
{
  "id": <str>,                      // scan ID
  "type": <responseType:str>,       // response object type
  "response": <object:interface>    // response payload as list of bytes
}
```
#### Response object types

*  "v1results" - v1 results object
*  "busy" - server is busy processing previous requests 
*  "notBusy" - server is not busy processing previous requests
*  "ready" - server is done processing request and results are ready  
*  "error" - error object

## API Examples
#### Default scan  

1. Trigger kubescape scan
  ```bash
  curl --header "Content-Type: application/json" --request POST --data '{"hostScanner":true}' http://127.0.0.1:8080/v1/scan
  ```

2. Get kubescape scan results
  ```bash
  curl --request GET http://127.0.0.1:8080/v1/results -o response.json
  ```

#### Trigger scan and wait for the scan to end  

```bash
curl --header "Content-Type: application/json" --request POST --data '{"hostScanner":true}' http://127.0.0.1:8080/v1/scan?wait -o scan_results.json
```
#### Scan single namespace with a specific framework
```bash
curl --header "Content-Type: application/json" \
  --request POST \
  --data '{"hostScanner":true, "includeNamespaces": ["kubescape"], "targetType": "framework", "targetNames": ["nsa"] }' \
  http://127.0.0.1:8080/v1/scan
```

#### Data profiling
Analyze profiled data using [pprof](https://github.com/google/pprof/blob/main/doc/README.md).
[How to use](https://pkg.go.dev/net/http/pprof)

example:
```bash
go tool pprof http://localhost:6060/debug/pprof/heap
```

## Examples

* [Prometheus](examples/prometheus/README.md)
* [Microservice](examples/microservice/README.md)


## Supported environment variables

* `KS_ACCOUNT`: Account ID
* `KS_EXCLUDE_NAMESPACES`: List of namespaces to exclude, e.g. `KS_EXCLUDE_NAMESPACES=kube-system,kube-public`
* `KS_INCLUDE_NAMESPACES`: List of namespaces to include, rest of the namespaces will be ignored. e.g. `KS_INCLUDE_NAMESPACES=dev,prod`
* `KS_HOST_SCAN_YAML`: Full path to the host scanner YAML
* `KS_FORMAT`: Output file format. default is json
* `KS_ENABLE_HOST_SCANNER`: Enable the host scanner feature
* `KS_DOWNLOAD_ARTIFACTS`: Download the artifacts every scan
* `KS_LOGGER_NAME`: Set logger name
* `KS_LOGGER_LEVEL`: Set logger level
