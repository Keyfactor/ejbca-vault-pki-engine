# v1.5.0
## Fixes
* Patched bug that required the `allow_any_name` or `allowed_domains=[""]` role parameters to issue/sign certificates with no CN.

## Chores
* Upgrade from Go `v1.21` to `v1.22`.
* Implement more strict golangci-lint policy.

## Features
* If upstream EJBCA API call fails, the HTTP status code is propogated to the Vault user via the Vault API status code.
* Implement OAuth 2.0 "client credentials" token flow as a supported authentication mechanism to EJBCA.

# v1.4.0
## Fixes
* Paths that need to write to the Storage backend now forward the request to the primary node. This is important in Enterprise HA deployments where Performance Standby Nodes are allowed to handle read requests/paths.

# v1.3.0
## Fixes
* Certificate revocation with the `/revoke*` paths now support revocation of certificates not in local Engine storage if a certificate is provided. Revoked certificates are stored in the revoked storage regardless of the initial role configuration used to issue the certificate.

# v1.2.0
## Features
* Create `revoke-with-key` path to revoke certificate only if user proves they have the private key
* Implement the following role restrictions for `issue` and `sign` paths:
    * `allow_localhost`
    * `allowed_domains`
    * `allow_bare_domains`
    * `allow_subdomains`
    * `allow_glob_domains`
    * `allow_wildcard_certificates`

## Fixes
* Mark the following paths to not require authentication to match in-tree PKI engine:
    * `cert/*` 
    * `ca/pem`
    * `ca_chain`
    * `ca`
    * `issuer/+/pem`
    * `issuer/+/der`
    * `issuer/+/json`
    * `issuers/`

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
