resource "kubernetes_deployment" "nginx" {
  metadata {
    name      = "nginx-typed"
    namespace = "default"
    labels = {
      app = "nginx"
    }
  }

  spec {
    replicas = 2

    selector {
      match_labels = {
        app = "nginx"
      }
    }

    template {
      metadata {
        labels = {
          app = "nginx"
        }
      }

      spec {
        container {
          name  = "nginx"
          image = "nginx:1.25"

          port {
            container_port = 80
          }
        }
      }
    }
  }
}
