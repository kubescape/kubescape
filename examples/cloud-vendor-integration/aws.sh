#!/bin/bash

# AWS
# Attach the Kubescape service account to an AWS IAM role with the described cluster permission

# Prerequisites:
# eksctl, awscli v2

# Set environment variables
echo 'Set environment variables'
export kubescape_namespace=kubescape
export kubescape_serviceaccount=armo-kubescape-service-account

# Get current context
echo 'Get current context'
export context=$(kubectl config current-context)

# Get cluster arn
echo 'Get cluster arn'
export cluster_arn=$(kubectl config view -o jsonpath="{.contexts[?(@.name == \"$context\")].context.cluster}")

# Get cluster name
echo 'Get cluster name'
export cluster_name=$(echo "$cluster_arn" | awk -F'/' '{print $NF}')

# Get cluster region
echo 'Get cluster region'
export cluster_region=$(echo "$cluster_arn" | awk -F':' '{print $4}')

# First step, Create IAM OIDC provider for the cluster (Not required if the third step runs as it is):
echo 'Create IAM OIDC provider for the cluster'
eksctl utils associate-iam-oidc-provider --cluster $cluster_name --approve

# Second step, Create a policy and service account role:
# Create a kubescape policy
echo 'Create a kubescape policy'
export kubescape_policy_arn=$(aws iam create-policy \
                --output yaml \
                --query 'Policy.Arn' \
    --policy-name kubescape \
    --policy-document \
"$(cat <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "eks:DescribeCluster",
            "Resource": "$cluster_arn"
        }
    ]
}
EOF
)")

# Create Kubernetes Kubescape service account, and AWS IAM attachment role
echo 'Create Kubernetes Kubescape service account, and AWS IAM attachment role'
eksctl create iamserviceaccount \
    --name $kubescape_serviceaccount \
    --namespace $kubescape_namespace \
    --cluster $cluster_name \
    --attach-policy-arn $kubescape_policy_arn \
    --approve \
    --override-existing-serviceaccounts

# Install/Upgrade Kubescape chart
echo 'Install/Upgrade Kubescape chart'
helm upgrade --install armo  armo-components/ -n kubescape --create-namespace --set clusterName=$cluster_name --set cloud_provider_engine=eks --set createKubescapeServiceAccount=false --set cloudRegion=$cluster_region
