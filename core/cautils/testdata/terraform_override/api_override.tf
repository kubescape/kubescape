# Replaces the whole spec block of kubernetes_pod_v1.api: nested blocks in an
# override are not merged with the original block, so host_pid is dropped.
resource "kubernetes_pod_v1" "api" {
  spec {
    host_network = false
    container {
      name  = "api"
      image = "nginx:1.27"
    }
  }
}
