resource "kubernetes_manifest" "bignum_test" {
  manifest = {
    apiVersion = "v1"
    kind       = "ConfigMap"
    metadata = {
      name = "bignum-test"
      annotations = {
        "big-number" = 9007199254740993
      }
    }
    data = {}
  }
}
