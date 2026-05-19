# Integrating with Jenkins CI/CD

Use Jenkins to scan your Kubernetes manifests for misconfigurations
with Kubescape. Scan results are published as part of your Jenkins
workflow.

## Prerequisites

- Jenkins 2.x with the [JUnit Plugin](https://plugins.jenkins.io/junit/)
- A Jenkins agent running on Linux (Ubuntu/Debian recommended)
- Network access to `GitHub.com` from the agent

## Freestyle Job (shell build step)

1. In Jenkins, create a **Freestyle** job.
2. Add an **Execute shell** build step to install and scan:

```shell
curl -s https://raw.githubusercontent.com/kubescape/kubescape/master/install.sh | /bin/bash
export PATH=$PATH:$HOME/.kubescape/bin
kubescape scan . --format junit --output results.xml --exclude-namespaces kube-system,kube-public
```

## Declarative Pipeline

Alternatively,you can integrate kubescape into a Jenkins Declarative Pipeline:

```groovy
pipeline {
    agent any
    environment {
        KUBESCAPE_RESULTS = 'kubescape-results.xml'
    }
    stages {
        stage('Install and Scan Kubescape') {
            steps {
                sh '''
                    curl -s https://raw.githubusercontent.com/kubescape/kubescape/master/install.sh | /bin/bash
                    export PATH=$PATH:$HOME/.kubescape/bin
                    kubescape scan . --format junit --output ${KUBESCAPE_RESULTS} --exclude-namespaces kube-system,kube-public
                '''
            }
        }
        stage('Publish Results') {
            steps {
                junit allowEmptyResults: true, testResults: "${KUBESCAPE_RESULTS}"
            }
        }
    }
    post {
        always {
            archiveArtifacts artifacts: "${KUBESCAPE_RESULTS}", allowEmptyArchive: true
        }
    }
}
kubescape scan framework nsa . --format junit --output kubescape-results.xml

