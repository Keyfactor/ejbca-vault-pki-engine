# v1.1.0
## Features
* Implement `ca_cert` field in config path for communication with EJBCA API that doesn't serve publically trusted certificate
    * Upgrade `ejbca-go-client-sdk` to `v0.1.5` that supports communication with non-publically trusted servers

## Chores
* Implement logging
* Update documentation

## Fixes
* Refactor `read` verb for `/config` path to redact private key in response

# v1.0.0
## Features
* First public release of EJBCA Vault PKI Engine
