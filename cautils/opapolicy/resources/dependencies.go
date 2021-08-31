package resources

var RegoCAUtils = `
package cautils

list_contains(lista,element) {
  some i
  lista[i] == element
}

# getPodName(metadata) = name {
# 	name := metadata.generateName
#}
getPodName(metadata) = name {
	name := metadata.name
}

#returns subobject ,sub1 is partial to parent,  e.g parent = {a:a,b:b,c:c,d:d}
# sub1 = {b:b,c:c} - result is {b:b,c:c}, if sub1={b:b,e:f} returns {b:b}
object_intersection(parent,sub1) = r{
  
  r := {k:p  | p := sub1[k]
              parent[k]== p
              }
}

#returns if parent contains sub(both are objects not sets!!)
is_subobject(sub,parent) {
object_intersection(sub,parent)  == sub
}
`

var RegoDesignators = `
package designators

import data.cautils
#functions that related to designators

#allowed_namespace
#@input@: receive as part of the input object "included_namespaces" list
#@input@: item's namespace as "namespace"
#returns true if namespace exists in that list
included_namespaces(namespace){
    cautils.list_contains(["default"],namespace)
}

#forbidden_namespaces
#@input@: receive as part of the input object "forbidden_namespaces" list
#@input@: item's namespace as "namespace"
#returns true if namespace exists in that list
excluded_namespaces(namespace){
    not cautils.list_contains(["excluded"],namespace)
}

forbidden_wlids(wlid){
    input.forbidden_wlids[_] == wlid
}

filter_k8s_object(obj) = filtered {
    #put 
    filtered := obj
    	#filtered := [ x | cautils.list_contains(["default"],obj[i].metadata.namespace) ; x := obj[i] ]
        # filtered := [ x | not cautils.list_contains([],filter1Set[i].metadata.namespace); x := filter1Set[i]]
        
}
`
var RegoKubernetesApiClient = `
package kubernetes.api.client

# service account token
token :=  data.k8sconfig.token

# Cluster host
host := data.k8sconfig.host

# default certificate path 
# crt_file := "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
crt_file := data.k8sconfig.crtfile

client_crt_file := data.k8sconfig.clientcrtfile
client_key_file := data.k8sconfig.clientkeyfile
 

# This information could be retrieved from the kubernetes API
# too, but would essentially require a request per API group,
# so for now use a lookup table for the most common resources.
resource_group_mapping := {
	"services": "api/v1",
	"pods": "api/v1",
	"configmaps": "api/v1",
	"secrets": "api/v1",
	"persistentvolumeclaims": "api/v1",
	"daemonsets": "apis/apps/v1",
	"deployments": "apis/apps/v1",
	"statefulsets": "apis/apps/v1",
	"horizontalpodautoscalers": "api/autoscaling/v1",
	"jobs": "apis/batch/v1",
	"cronjobs": "apis/batch/v1beta1",
	"ingresses": "api/extensions/v1beta1",
	"replicasets": "apis/apps/v1",
	"networkpolicies": "apis/networking.k8s.io/v1",
	"clusterroles": "apis/rbac.authorization.k8s.io/v1",
	"clusterrolebindings": "apis/rbac.authorization.k8s.io/v1",
	"roles": "apis/rbac.authorization.k8s.io/v1",
	"rolebindings": "apis/rbac.authorization.k8s.io/v1",
	"serviceaccounts": "api/v1"
}

# Query for given resource/name in provided namespace
# Example: query_ns("deployments", "my-app", "default")
query_name_ns(resource, name, namespace) = http.send({
		"url": sprintf("%v/%v/namespaces/%v/%v/%v", [
		host,
		resource_group_mapping[resource],
		namespace,
		resource,
		name,
	]),
	"method": "get",	
	"headers": {"authorization": token},
	"tls_client_cert_file": client_crt_file,
	"tls_client_key_file": client_key_file,
	"tls_ca_cert_file": crt_file,
	"raise_error": true,
})

# Query for given resource type using label selectors
# https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/#api
# Example: query_label_selector_ns("deployments", {"app": "opa-kubernetes-api-client"}, "default")
query_label_selector_ns(resource, selector, namespace) = http.send({
	"url": sprintf("%v/%v/namespaces/%v/%v?labelSelector=%v", [
		host,
		resource_group_mapping[resource],
		namespace,
		resource,
		label_map_to_query_string(selector),
	]),
	"method": "get",
	"headers": {"authorization": token},
	"tls_client_cert_file": client_crt_file,
	"tls_client_key_file": client_key_file,
	"tls_ca_cert_file": crt_file,
	"raise_error": true,
})

# x := field_transform_to_qry_param("spec.selector",input)
# input = {"app": "acmefit", "service": "catalog-db"}
# result:  "spec.selector.app%3Dacmefit,spec.selector.service%3Dcatalog-db"


query_field_selector_ns(resource, field, selector, namespace) = http.send({
	"url": sprintf("%v/%v/namespaces/%v/%v?fieldSelector=%v", [
		host,
		resource_group_mapping[resource],
		namespace,
		resource,
		field_transform_to_qry_param(field,selector),
	]),
	"method": "get",
	"headers": {"authorization": token},
	"tls_client_cert_file": client_crt_file,
	"tls_client_key_file": client_key_file,
	"tls_ca_cert_file": crt_file,
	"raise_error": true,
	
})

# # Query for all resources of type resource in all namespaces
# # Example: query_all("deployments")
# query_all(resource) = http.send({
# 	"url": sprintf("https://%v:%v/%v/%v", [
# 		ip,
# 		port,
# 		resource_group_mapping[resource],
# 		resource,
# 	]),
# 	"method": "get",
# 	"headers": {"authorization": sprintf("Bearer %v", [token])},
# 	"tls_client_cert_file": crt_file,
# 	"raise_error": true,
# })

# Query for all resources of type resource in all namespaces
# Example: query_all("deployments")
query_all(resource) = http.send({
	"url": sprintf("%v/%v/%v", [
		host,
		resource_group_mapping[resource],
		resource,
	]),
	"method": "get",
	"headers": {"authorization": token},
	"tls_client_cert_file": client_crt_file,
	"tls_client_key_file": client_key_file,
	"tls_ca_cert_file": crt_file,
	"raise_error": true,
}) 



# Query for all resources of type resource in all namespaces - without authentication
# Example: query_all("deployments")
query_all_no_auth(resource) = http.send({
	"url": sprintf("%v/%v/namespaces/default/%v", [
		host,
		resource_group_mapping[resource],
		resource,
	]),
	"method": "get",
	"raise_error": true,
	"tls_insecure_skip_verify" : true,
}) 

field_transform_to_qry_param(field,map) = finala {
	mid := {concat(".",[field,key]): val | val := map[key]}
    finala := label_map_to_query_string(mid)
}
label_map_to_query_string(map) = concat(",", [str | val := map[key]; str := concat("%3D", [key, val])])
`
