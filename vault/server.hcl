plugin_directory = "/Users/adrien/Documents/horizon-secrets-engine/vault/plugins"
api_addr         = "http://localhost:9000"

storage "inmem" {}

listener "tcp" { 
  address     = "localhost:9000"
  tls_disable = "true"
}

