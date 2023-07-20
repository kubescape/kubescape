package resourcehandler

type QueryableResources map[string]QueryableResource

// QueryableResource is a struct that holds a representation of a resource we would like to query (from the K8S API, or from other sources)
type QueryableResource struct {
	// <api group/api version/resource>
	GroupVersionResourceTriplet string
	// metadata.name==<resource name>, metadata.namespace==<resource namespace> etc.
	FieldSelectors string
}
