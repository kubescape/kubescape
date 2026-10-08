---
references:
  - kind: code
    role: implementation
    target: httphandler/handlerequests/v1/requestshandler.go#Scan
  - kind: code
    role: implementation
    target: httphandler/handlerequests/v1/requestshandlerutils.go#watchForScan
  - kind: code
    role: implementation
    target: httphandler/handlerequests/v1/serverstate.go
  - kind: doc
    role: intent
    target: httphandler/docs/swagger.yaml
---

# Scan request

A scan an API client asked the Kubescape Microservice to run, tracked by its scan
ID until its results are collected or deleted. Work it accepted carries on even
when the client disconnects.

## Information kept

- **Scan ID** — the identifier the Product assigns when it accepts the request
- **Targets** — the frameworks or controls to evaluate; every framework when none are named
- **Namespaces** — the namespaces included or excluded, replacing the configured filters when given
- **Callback URL** — where the Product reports the scan's completion or failure, when the client registered one
- **Report** — the scan results, once the scan completes
- **Error** — why the scan failed, with file paths removed

## States

### Running

Accepted and waiting in the queue or being scanned; the API answers busy.

### Completed

Finished with results ready to collect.

### Failed

Finished without results; collecting it returns the error.
