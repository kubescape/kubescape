# Providers

Kubescape results are a very useful input to security services.  Here are a list of commercial services that are compatible with Kubescape.  If you develop one, please send a PR to add it to this list!

### ARMO Platform

ARMO Platform is the enterprise solution based on, and powered by Kubescape. It’s a ​​multi-cloud Kubernetes and CI/CD security platform with a single pane of glass. Features include risk analysis, security compliance, misconfiguration, image vulnerability, repository and registry scanning, RBAC visualization, and more. The Community Edition is free forever! [Get started today](https://cloud.armosec.io/account/sign-up?utm_source=github&utm_medium=repository).

### Red Hat Quay (`quay.io`)

Kubescape supports retrieving vulnerability reports and security scan statuses directly from Red Hat Quay, both the public SaaS registry at `quay.io` and private, self-hosted Red Hat Quay enterprise deployments. See [providers/quay.md](providers/quay.md) for authentication, configuration, and usage details.
