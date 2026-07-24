#!/bin/bash

# GCP
# Attach the Kubescape service account to a GCP service account with the get cluster permission

# Prerequisites:
# gcloud
# Workload Identity enabled on the cluster.
# Node pool with --workload-metadata=GKE_METADATA where the pod can run. 
# CLUSTER_NAME and CLUSTER_REGION environment variables.

[ -z $CLUSTER_NAME ] && >&2 echo "Please set the CLUSTER_NAME environment variable" && exit 1
[ -z $CLUSTER_REGION ] && >&2 echo "Please set the CLUSTER_REGION environment variable" && exit 1

# Create GCP service account
gcloud iam service-accounts create kubescape --display-name=kubescape

# Set environment variables
echo 'Set environment variables'
export kubescape_namespace=kubescape
export kubescape_serviceaccount=armo-kubescape-service-account

# Get current GCP project
echo 'Get current GCP project'
export gcp_project=$(gcloud config get-value project)

sleep 5
# Get service account email
echo 'Get service account email'
export gcp_service_account=$(gcloud iam service-accounts list --filter="email ~ kubescape@" --format="value(email)")

# Create custome cluster.get role
echo 'Create custome cluster.get role'
export custom_role_name=$(gcloud iam roles create kubescape --project=$gcp_project --title='Armo kubernetes' --description='Allow clusters.get to Kubernetes armo service account' --permissions=container.clusters.get --stage=GA  --format='value(name)')

# Attach policies to the service account
echo 'Attach policies to the service account'
gcloud --quiet projects add-iam-policy-binding $gcp_project --member serviceAccount:$gcp_service_account --role $custom_role_name >/dev/null
gcloud --quiet projects add-iam-policy-binding $gcp_project --member serviceAccount:$gcp_service_account --role roles/storage.objectViewer >/dev/null

# If there are missing permissions, use this role instead
# gcloud --quiet projects add-iam-policy-binding $gcp_project --member serviceAccount:$gcp_service_account --role roles/container.clusterViewer

# Bind the GCP kubescape service account to kubescape kubernetes service account
gcloud iam service-accounts add-iam-policy-binding $gcp_service_account --role roles/iam.workloadIdentityUser --member "serviceAccount:${gcp_project}.svc.id.goog[${kubescape_namespace}/${kubescape_serviceaccount}]"

# Install/Upgrade Kubescape chart
echo 'Install/Upgrade Kubescape chart'
helm upgrade --install armo  armo-components/ -n kubescape --create-namespace --set cloud_provider_engine=gke --set gke_service_account=$gcp_service_account --set cloudRegion=$CLUSTER_REGION --set clusterName=$CLUSTER_NAME --set gkeProject=$gcp_project
