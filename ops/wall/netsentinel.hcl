# NetSentinel may read only its own secrets and its own rotating DB credential.
path "kv/data/netsentinel/*"                 { capabilities = ["read"] }
path "database/static-creds/netsentinel-db"  { capabilities = ["read"] }
