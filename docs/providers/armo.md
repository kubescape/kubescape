<img src="armo-powered-by-kubescape-logo-grey.svg" width="25%" height="25%" align="right">

[ARMO Platform](https://cloud.armosec.io/account/sign-up?utm_source=ARMOgithub&utm_medium=ARMOcli) is an enterprise solution based on Kubescape. It’s a multi-cloud Kubernetes and CI/CD security platform with a single pane of glass including risk analysis, security compliance, misconfiguration, image vulnerability, repository and registry scanning, RBAC visualization, and more.

## Connect Kubescape to ARMO Platform
Step #1: Install Kubescape in your CLI
```
curl -s https://raw.githubusercontent.com/kubescape/kubescape/master/install.sh | /bin/bash
```
Step #2: Run
```
kubescape scan --enable-host-scan --verbose --submit --create-account
```

Step #3: Your scan results will be sent to ARMO Platform, and you'll be given a URL to see them!

## Key features: 

💪 DevSecOps Dashboard: A single pane of glass for different security and DevOps stakeholders, providing each with the information they need, within the required context, and creating a common language between them.

💪 Enterprise Support: Additional support options including escalation options, response SLA, and a dedicated account manager.

💪 Premium Plugins: Plugins for collaboration tools such as Slack and Jira to enhance collaboration capabilities and provide more context to workflows.

💪 Multi-user and Multi-tenancy: Support for multiple users to access the same account and separate departments in an enterprise to use the same instance of ARMO Platform.

💪 Authentication & Security: Third-party authentication SSO using SAML or OIDC and user access and permission management.

💪 Data retention: Data retention capabilities to meet compliance and regulation policies.

💪 RBAC visualizer: an interactive tool for easy monitoring of Kubernetes access permissions.


<img src="armo-platform-dashboard.png">
