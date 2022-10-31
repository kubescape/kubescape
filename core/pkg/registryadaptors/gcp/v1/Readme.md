# GCP Adaptor

### How we add gcp adaptor

As there can be possiblities of use of multiple registries we check for each adaptor if we have required credentias. For every adaptor having credentials we append the adaptor to the adaptors slice.

Particularly for gcp, we frstly bring the `gcpCloudAPI` from the connector. We still haven't created a proper function that initiats the gcpCloudAPI with projectId, credentialsPath, credentialsCheck fields. We check for `credentialsCheck` bool which is set true when we have credentials(to be set when initializing the gcpCloudAPI) 

### How we fetch vulnerabilities for images

Step 1: 
    Get container analysis client 
    For this we needs credentials of the service account. Out of few approaches here we are using [JSON key file](https://cloud.google.com/container-registry/docs/advanced-authentication#json-key) for credentials and path to this file should be stored in `credentialsPath`

Step 2: 
    Do ListOccurrenceRequest 
    For this we need the `projectID` and the `resourceUrl`. ProjectID should be provided by the users and resourceUrl is processed imageTag that we get from kubescape resources
  
Step 3:
    Get Occurrence iterator
    We use context and the request from the ListOccurenceRequest to get the iterators


### How we convert the response to Vulnerabilities

Response from the iterator has two type of kinds i.e. Discovery and Vulnerabilties and both has differnent struct

### How can this adaptor be used by the user 

To know about GCR service accounts follow https://cloud.google.com/container-registry/docs/gcr-service-account
export variables 
    `export KS_GCP_CREDENTIALS_PATH=<path to service account credentials file>`
    `export KS_GCP_PROJECT_ID=<your project ID>`
