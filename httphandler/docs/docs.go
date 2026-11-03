// Package classification Kubescape Microservice
//
// The Kubescape Microservice API allows clients to interact with a Kubescape instance running in a Kubernetes cluster: trigger scans, retrieve and delete their results, enable exporting metrics to Prometheus etc.
//
//	Schemes: http
//	BasePath: /
//	Version: 1.0.0
//
//	Consumes:
//	- application/json
//
//	Produces:
//	- application/json
//
//	Security:
//	- bearer
//
//	SecurityDefinitions:
//	bearer:
//	     type: apiKey
//	     name: Authorization
//	     in: header
//	     description: Kubernetes service-account token with audience kubescape.io
//
// swagger:meta
package docs
