resource "kubernetes_manifest" "web" {
  manifest = {
    apiVersion = "v1"
    kind       = "Pod"
    metadata = {
      name      = "web"
      namespace = "default"
    }
    spec = {
      hostNetwork = false
      containers = [{
        name  = "web"
        image = "nginx:1.25"
      }]
    }
  }
}
