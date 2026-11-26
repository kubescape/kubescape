resource "kubernetes_manifest" "web" {
  manifest = {
    apiVersion = "v1"
    kind       = "Pod"
    metadata = {
      name      = "web"
      namespace = "default"
    }
    spec = {
      hostNetwork = true
      containers = [{
        name  = "web"
        image = "nginx:1.25"
      }]
    }
  }
}

resource "kubernetes_pod_v1" "api" {
  metadata {
    name      = "api"
    namespace = "default"
  }
  spec {
    host_network = true
    host_pid     = true
    container {
      name  = "api"
      image = "nginx:1.25"
    }
  }
}
