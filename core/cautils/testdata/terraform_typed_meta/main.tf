resource "kubernetes_config_map" "dependency" {
  metadata {
    name = "dependency-config"
  }
  data = {}
}

resource "kubernetes_stateful_set" "web" {
  depends_on = [kubernetes_config_map.dependency]
  count      = 1

  lifecycle {
    prevent_destroy = true
  }

  metadata {
    name = "web"
  }

  spec {
    service_name = "web"
    replicas     = 1

    selector {
      match_expressions {
        key      = "app"
        operator = "In"
        values   = ["web"]
      }
    }

    volume_claim_template {
      metadata {
        name = "www"
      }
      spec {
        access_modes = ["ReadWriteOnce"]
      }
    }

    template {
      metadata {
        labels = {
          app = "web"
        }
      }
      spec {
        container {
          name  = "web"
          image = "nginx:1.25"

          readiness_probe {
            http_get {
              path = "/healthz"
              port = 80

              http_header {
                name  = "X-Custom-Header"
                value = "Awesome"
              }
            }
          }
        }
      }
    }
  }
}
