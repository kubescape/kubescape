## Overview
Kubernetes v1.28+ introduced native ValidatingAdmissionPolicy powered by CEL. Currently, users must choose between out-of-cluster Rego admission or manual VAP objects.

## Problem
Converting complex Rego rules with comprehensions and cross-resource lookups into efficient CEL ASTs is non-trivial and often breaches the 1,000,000 cost unit ceiling on large objects.

## Solution
Implement a Rego AST parser to walk rule bodies and generate native CEL AST trees. Add an AST optimizer for constant folding and short-circuit pruning. Emit production-ready ValidatingAdmissionPolicy manifests.
