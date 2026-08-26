resource "kubernetes_manifest" "bignum_test" {
  manifest = {
    apiVersion = "v1"
    kind       = "ConfigMap"
    metadata = {
      name       = "bignum-test"
      generation = 9007199254740993
    }
    data = {}
  }
}
