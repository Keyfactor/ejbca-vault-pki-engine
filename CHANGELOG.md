# v1.5.1
## Fixes
* Patched bug that allowed the `allowed_uri_sans` role parameter to be bypassed when issuing/signing certificates with URI SANs.
* Patched bug that allowed the `allowed_other_sans` role parameter to be bypassed when issuing/signing certificates with other (otherName) SANs. Requested other SANs are now matched against the role's `allowed_other_sans` patterns on both the issue and sign paths, and malformed `allowed_other_sans` role config is rejected at role-create time.
* Fixed a panic (index out of range) when fetching a CA bundle for a CA name that does not exist in EJBCA, or when EJBCA returns an empty certificate chain. These cases now return a clear error.
* Fixed a cross-mount interaction and data race caused by a package-global default CA name being mutated at runtime. The default CA is now resolved per-request from the mount's stored configuration.
* Fixed leased certificates issued with `format=der` not being revoked in EJBCA on lease expiry/revoke. Lease revocation now resolves the certificate by the serial number stored in the lease's internal data, independent of the response format.

* Corrected misleading documentation and path help that claimed a supplied `certificate` must have been issued by this mount to be revoked. Revocation by supplied certificate is actually bounded by the configured EJBCA service account's permissions; the docs now describe the real behavior.
* Fixed `end_entity_name=ip` producing the literal end-entity name `"ip"` when the request had no IP SAN; it now falls through to an error like the other `cn`/`dns`/`uri` selectors.
* Added the configured `end_entity_name` to the role read response, which previously omitted it.
* Fixed fetching an unknown certificate serial returning an HTTP 500. A serial not stored by this mount is now reported as a client-facing not-found error rather than an internal error.
* Fixed the `default_end_entity_name` config field being unconfigurable due to a misspelled schema key (`default_end_endity_profile`). The field is now correctly named and returned by config read.

## Features
* Added an optional `revocation_reason` parameter to the `/revoke` and `/revoke-with-key` paths, accepting any RFC 5280 reason code and defaulting to `CESSATION_OF_OPERATION` (the previous hardcoded value).

# v1.5.0
## Fixes
* Patched bug that required the `allow_any_name` or `allowed_domains=[""]` role parameters to issue/sign certificates with no CN.
* Security: enforce the role's `allowed_uri_sans` restriction. Previously URI SANs were only checked to see whether the role permitted any URI SANs at all; individual URIs were never matched against the configured patterns, allowing certificates to be issued or signed with arbitrary URI SANs.

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
