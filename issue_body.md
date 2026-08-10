## Overview
Currently, Kubescape directly queries the admissionregistration.k8s.io/v1 API group for ValidatingAdmissionPolicies (VAPs). This fails on older clusters (< v1.30 or < v1.26) where the endpoint is either non-existent or only exists as v1beta1, causing the entire scan to fail with an API routing error.

## Problem
Older clusters do not support v1 of VAPs and failing the scan entirely because of this is poor user experience.

## Solution
Implement dynamic API group discovery before querying VAP resources and gracefully fall back to v1beta1 or skip the VAP reconciliation phase if VAPs are not supported, issuing a warning instead of failing the scan.
