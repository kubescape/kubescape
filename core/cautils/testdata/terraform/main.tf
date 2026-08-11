variable "namespace" {
  default = "default"
}

resource "kubernetes_manifest" "test_deployment" {
  manifest = {
    apiVersion = "apps/v1"
    kind       = "Deployment"
    metadata = {
      name      = "nginx"
      namespace = var.namespace
    }
    spec = {
      replicas = 1
      selector = {
        matchLabels = { app = "nginx" }
      }
      template = {
        metadata = { labels = { app = "nginx" } }
        spec = {
          containers = [
            {
              name  = "nginx"
              image = "nginx:1.25"
            }
          ]
        }
      }
    }
  }
}
