# Container image vulnerability adaptor interface

## High level design of Kubescape

### Layers

* Controls and Rules: that actual control logic implementation, the "tests" themselves. Implemented in rego.
* OPA engine: the [OPA](https://github.com/open-policy-agent/opa) rego interpreter.
* Rules processor: Kubescape component, it enumerates and runs the controls while preparing all of the input data that the controls need for running.
* Data sources: set of different modules providing data to the Rules processor so it can run the controls with them. Examples: Kubernetes objects, cloud vendor API objects and adding in this proposal the vulnerability information.
* Cloud Image Vulnerability adaption interface: the subject of this proposal, it gives a common interface for different registry/vulnerability vendors to adapt to.
* CIV adaptors: specific implementation of the CIV interface, example Harbor adaption.
```
 -----------------------
| Controls/Rules (rego) |
 -----------------------
            |
 -----------------------
|      OPA engine       |
 -----------------------
            |
 -----------------------
|    Rules processor    |
 ----------------------- 
            |
 -----------------------
|     Data sources      |
 -----------------------              
            |
 =======================
| CIV adaption interface|    <- Adding this layer in this proposal
 ======================= 
            |
 -----------------------
| Specific CIV adaptors |    <- Will be implemented based on this proposal
 -----------------------      

        

```

## Functionalities to cover

The interface needs to cover the following functionalities:

* Authentication against the information source (abstracted login)
* Triggering image scan (if applicable, the source might store vulnerabilities for images but cannot scan alone)
* Reading image scan status (with last scan date and etc.)
* Getting vulnerability information for a given image
* Getting image information
  * Image manifests
  * Image BOMs (bill of material)

## Go API proposal

```go

/*type ContainerImageRegistryCredentials struct {
	Password string
	Tag        string
	Hash       string
}*/

type ContainerImageIdentifier struct {
	Registry   string
	Repository string
	Tag        string
	Hash       string
}

type ContainerImageScanStatus struct {
	ImageID         ContainerImageIdentifier
	IsScanAvailable bool
	IsBomAvailable  bool
	LastScanDate    time.Time
}

type ContainerImageVulnerabilityReport struct {
	ImageID ContainerImageIdentifier
	// TBD
}

type ContainerImageInformation struct {
	ImageID       ContainerImageIdentifier
	Bom           []string
	ImageManifest Manifest // will use here Docker package definition
}

type IContainerImageVulnerabilityAdaptor interface {
	// Credentials are coming from user input (CLI or configuration file) and they are abstracted at string to string map level
	// so an example use would be like registry: "simpledockerregistry:80" and credentials like {"username":"joedoe","password":"abcd1234"}
	Login(registry string, credentials map[string]string) error

	// For "help" purposes
	DescribeAdaptor() string

	GetImagesScanStatus(imageIDs []ContainerImageIdentifier) ([]ContainerImageScanStatus, error)

	GetImagesVulnerabilties(imageIDs []ContainerImageIdentifier) ([]ContainerImageVulnerabilityReport, error)

	GetImagesInformation(imageIDs []ContainerImageIdentifier) ([]ContainerImageInformation, error)
}
```



# Integration

# Input

The objects received from the interface will be converted to an IMetadata compatible objects as following

```json
{
    "apiVersion": "armo.vuln.images/v1",
    "kind": "ImageVulnerabilities",
    "metadata": {
        "name": "nginx:latest"
    },
    "data": {
        // list of vulnerabilities
    }
}
```


# Output

The rego results will be a combination of the k8s artifact and the list of relevant CVEs for the control

```json
{
    "apiVersion": "armo.vuln/v1",
    "kind": "Pod",
    "metadata": {
        "name": "nginx"
        "namespace": "default"

    },
    "relatedObjects": [
        {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "nginx"
                "namespace": "default"
            },
            "spec": {
                // podSpec
            },
        },
        {
            "apiVersion": "image.vulnscan.com/v1",
            "kind": "ImageVulnerabilities",
            "metadata": {
                "name": "nginx:latest",
            },
            "data": {
                // list of vulnerabilities
            }
        }
    ]
}
```
