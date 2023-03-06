plugin_directory = "/Users/adrien/Documents/horizon-secret-engine/vault/plugins"
api_addr = "http://127.0.0.1:8200"

storage "inmem" {}

listener "tcp" {
  address     = "127.0.0.1:8200"
  tls_disable = "true"
}
