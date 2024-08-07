# Get started with the EJBCA PKI Secrets Engine

The EJBCA PKI Secrets Engine is a Vault plugin that replicates the built-in Vault PKI secrets engine, but processes requests through EJBCA instead of through Vault. The plugin was designed to be swapped for the built-in Vault PKI secrets engine with minimal changes to existing Vault configurations.

The secrets engine is built on top of the [EJBCA REST API](https://doc.primekey.com/ejbca/ejbca-operations/ejbca-ca-concept-guide/protocols/ejbca-rest-interface) and uses the [EJBCA Go Client SDK](https://github.com/Keyfactor/ejbca-go-client-sdk) for programmatic access. 

## EJBCA API Usage
The EJBCA PKI Secrets Engine requires the following API endpoints:
* `GET /v1/ca/{subject_dn}/certificate/download` - Used to fetch CA certificates and certificate chains based on the CA's subject DN.
* `GET /v1/ca` - Used to verify the CA name provided as `issuer_ref`.
* `PUT /v1/certificate/{issuer_dn}/{certificate_serial_number}/revoke` - Used to revoke certificates.
* `POST /v1/certificate/pkcs10enroll` - Used to issue certificates.

## Requirements
### To build
* [Git](https://git-scm.com/)
* [Golang](https://golang.org/) >= v1.22

### To use
* EJBCA [Community](https://www.ejbca.org/) or EJBCA [Enterprise](https://www.keyfactor.com/products/ejbca-enterprise/)
  * The "REST Certificate Management" protocol must be enabled under System Configuration > Protocol Configuration.
* [HashiCorp Vault](https://www.vaultproject.io/) >= v1.11.0

## Installation
<details><summary>From Source</summary>

Clone the repository and build the plugin.
```shell
git clone https://github.com/Keyfactor/ejbca-vault-pki-engine.git
cd ejbca-vault-pki-engine
```

Build the plugin for your platform.
```shell
go build -o ejbca-vault-pki-engine cmd/ejbca-pki/main.go -v
````

Calculate the SHA256 checksum of the plugin.
```shell
SHA256=$(sha256sum ejbca-vault-pki-engine | cut -d ' ' -f1)
```

Move the plugin to the Vault plugin directory.
```shell
sudo mv ejbca-vault-pki-engine </path/to/vault/plugins>
```

Register SHA256 checksum of the plugin with Vault.
```shell
vault write sys/plugins/catalog/secret/ejbca-vault-pki-engine sha_256=$SHA256 command="ejbca-vault-pki-engine" version="v1.2.0"
```

Mount the secrets engine and choose a prefix for the path (recommended is `ejbca`).
```shell
vault secrets enable -path=ejbca -plugin-name=ejbca-vault-pki-engine plugin
```
</details>

<details><summary>From GitHub Release</summary>

Download and extract the latest release for your platform.
```shell
OS=$(go env GOOS)
ARCH=$(go env GOARCH)
curl -L https://github.com/Keyfactor/ejbca-vault-pki-engine/releases/latest/download/ejbca-vault-pki-engine-$OS-$ARCH.tar.gz
tar xzf ejbca-vault-pki-engine-$OS-$ARCH.tar.gz
```

Calculate the SHA256 checksum of the plugin.
```shell
SHA256=$(sha256sum ejbca-vault-pki-engine | cut -d ' ' -f1)
````

Move the plugin to the Vault plugin directory.
```shell
sudo mv ejbca-vault-pki-engine </path/to/vault/plugins>
```

Register SHA256 checksum of the plugin with Vault.
```shell
vault write sys/plugins/catalog/secret/ejbca-vault-pki-engine sha_256=$SHA256 command="ejbca-vault-pki-engine" version="v1.2.0"
```

Mount the secrets engine and choose a prefix for the path (recommended is `ejbca`).
```shell
vault secrets enable -path=ejbca -plugin-name=ejbca-vault-pki-engine plugin
```
</details>

## Configuration

The EJBCA Vault PKI Engine has two levels of configuration.

* The `/config` path configures the connection to EJBCA and contains default values for the EJBCA-specific configuration fields. Default configuration fields are provided in case you already use the in-tree Vault PKI Engine and want to deploy the EJBCA Secrets Engine with minimal intervention.
* The `/roles` endpoint configures how the engine should behave when issuing certificates, and configures the validations/requirements for the attributes included in signed certificates. The EJBCA Vault PKI Engine implements a subset of the fields implemented by the in-tree Vault PKI Engine.

The `/config` endpoint must be configured first. The following table describes the available fields.

| Configuration                 | Description                                                                                                                                                                                                        |
|-------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `hostname`                    | The hostname of the connected EJBCA server.                                                                                                                                                                        |
| `ca_cert`                     | (optional) The CA certificate(s) used to validate the EJBCA server's certificate. Certificates must be in PEM format.                                                                                              |
| `client_cert`                 | The client certificate (public key only) used to authenticate to EJBCA. Must be in PEM format.                                                                                                                     |
| `client_key`                  | The client key matching `client_cert` used to authenticate to EJBCA. Must be an unencrypted PKCS#8 private key in PEM format.                                                                                      |
| `token_url`                   | The OAuth 2.0 token URL used to obtain an access token.                                                                                                                                                            |
| `client_id`                   | The OAuth 2.0 client ID used to obtain an access token.                                                                                                                                                            |
| `client_secret`               | The OAuth 2.0 client secret used to obtain an access token.                                                                                                                                                        |
| `scopes`                      | (optional) A comma-separated list of OAuth 2.0 scopes used to obtain an access token.                                                                                                                              |
| `audience`                    | (optional) The OAuth 2.0 audience used to obtain an access token.                                                                                                                                                  |
| `default_ca`                  | The default CA in EJBCA that will be used to issue certificates if not specified by the role or per-request.                                                                                                       |
| `default_end_entity_profile`  | The name of an end entity profile in the connected EJBCA instance that will be used to issue certificates if not specified by the role or per-request.                                                             |
| `default_certificate_profile` | The name of a certificate profile in the connected EJBCA instance that is configured to issue certificates if not specified by the role or per-request.                                                            |
| `default_end_entity_name`     | (optional) The name of the end entity, or configuration for how the EJBCA UpstreamAuthority should determine the end entity name. See [End Entity Name Customization](#configuring-end-entity-name) for more info. |

### mTLS vs OAuth 2.0

The EJBCA Vault PKI Engine can authenticate to EJBCA using mTLS (client certificate) or using the OAuth 2.0 "client credentials" token flow (sometimes called two-legged OAuth 2.0).

> [EJBCA Enterprise](https://www.keyfactor.com/products/ejbca-enterprise/) is required for the OAuth 2.0 "client credentials" token flow. EJBCA Community only supports mTLS (client certificate) authentication.

To configure the plugin to use mTLS, you must configure the `/config` object with **both** of the following fields:

* `client_cert`
* `client_key`

Use the following vault command to create the `config` object with mTLS:

```shell
vault write ejbca/config \
    hostname="https://ejbca.example.com:8443/ejbca" \
    client_cert=@/path/to/client/cert.pem \
    client_key=@/path/to/client/key.pem \
    ca_cert=@/path/to/ca/cert.pem \
    end_entity_profile_name="MyEndEntityProfile" \
    certificate_profile_name="MyCertificateProfile"
```

To configure the plugin to use OAuth 2.0, you must configure the `/config` object with the following fields:

* `token_url`
* `client_id`
* `client_secret`
* (optional) `scopes`
* (optional) `audience`

Use the following vault command to create the `config` object with OAuth 2.0:


```shell
vault write ejbca/config \
    hostname="https://ejbca.example.com:8443/ejbca" \
    token_url="https://dev.idp.com/oauth/token" \
    client_id="<client_id>" \
    client_secret="<client_secret>" \
    scopes="<comma separated list of scopes>" \
    audience="<OAuth audience>" \
    ca_cert=@/path/to/ca/cert.pem \
    end_entity_profile_name="MyEndEntityProfile" \
    certificate_profile_name="MyCertificateProfile"
```

## Roles
The EJBCA PKI Secrets Engine supports a subset of the role fields as the built-in Vault PKI secrets engine, and for most usecases, can be used as a drop-in replacement. Use the following command to get descriptions for these fields:
```shell
vault path-help ejbca/roles/name
```

> EJBCA implements its own [role and policy system](https://doc.primekey.com/ejbca/ejbca-operations/ejbca-ca-concept-guide/end-entities-overview/end-entity-profiles-overview). Users should be advised that even if Certificate Enrollment with the EJBCA Vault PKI Engine is valid against the Vault role, it may still be rejected by EJBCA due to EJBCA's own role and policy system.
>
> Concequentially, there may be differences between how the EJBCA Vault PKI Engine and the built-in Vault PKI Engine handle certificate issuance and validation. If you are using the EJBCA Vault PKI Engine as a drop-in replacement for the built-in Vault PKI Engine, it is recommended to test the EJBCA Vault PKI Engine in a non-production environment before deploying it to production.
> 
> Please submit an issue if you encounter any differences between the EJBCA Vault PKI Engine and the built-in Vault PKI Engine.

The following example creates a basic role that can be used for issuance:
```shell
vault write ejbca/roles/example-dot-com \
    allow_any_name=true \
    allow_subdomains=true \
    max_ttl=8760h \
    key_type="rsa" \
    key_bits=2048 \
    signature_bits=256 \
    use_pss=false
```

The EJBCA PKI Secrets Engine also supports the following additional role fields that are not needed in the in-tree Vault PKI engine.

- `end_entity_profile_name` - The name of the EJBCA End Entity Profile to use for certificate issuance.
- `certificate_profile_name` - The name of the EJBCA Certificate Profile to use for certificate issuance.
- `end_entity_name` - A value that will either be used to calculate the end entity name, or the end entity name itself. See the (configuring end entity name)[#configuring-end-entity-name] for more details.
- `account_binding_id` - EJBCA Account Binding ID.

> **Note:** If left blank, the `end_entity_profile_name`, `certificate_profile_name`, and `end_entity_name` fields will default to the values configured in the `config` object.

### Vault Lease

The EJBCA Vault PKI Engine can create [Vault Leases](https://developer.hashicorp.com/vault/docs/concepts/lease) for issued certificates if the role has `generate_lease=true`. If this option is set, the lease and certificate that it represents can be revoked with `vault revoke <lease_id>`. When the lease is revoked, the engine revokes the certificate in EJBCA and updates the backend accordingly for the regular paths.

## Path Overview

Once the EJBCA PKI Secrets Engine is configured and roles are created, you can use the following paths to issue and sign certificates, list certificates, and revoke certificates.

### Issue/Sign Paths
The following paths can be used to issue and sign certificates. The `:role_name` parameter is required for all paths except `sign-verbatim`. Paths that require the `:issuer_ref` parameter will use the provided name as the EJBCA CA name for certificate issuance.

> **Note:** The `/issue` paths generate the CSR and private key on the Vault server - the private key is never sent over the wire by EJBCA.

| Path                                          | Issuer        | CSR required | Subject to role restriction | Description                                                                                                                          | Help Path                                            |
|-----------------------------------------------|---------------|--------------|-----------------------------|--------------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------|
| sign/:role_name                               | Role selected | Yes          | Yes                         | Sign a CSR using the default CA from Config and validate its attributes against the provided role.                                   | `vault path-help ejbca/sign/example`                 | 
| issuer/:issuer_ref/sign/:role_name            | Path selected | Yes          | Yes                         | Sign a CSR using a specific CA and validate its attributes against the provided role                                                 | `vault path-help ejbca/issuer/example/sign/example`  |
| issue/:role_name                              | Role selected | No           | Yes                         | Generate a private key configured either by the role or with the request itself, then sign the CSR using the default CA from Config. | `vault path-help ejbca/issue/example`                |
| issuer/:issuer_ref/issue/:role_name           | Path selected | No           | Yes                         | Generate a private key configured either by the role or with the request itself, then sign the CSR using the provided CA.            | `vault path-help ejbca/issuer/example/issue/example` |
| sign-verbatim(/:role_name)                    | default       | Yes          | No                          | Sign a CSR using the default CA and don't validate its attributes against a role.                                                    | `vault path-help ejbca/sign-verbatim`                |
| issuer/:issuer_ref/sign-verbatim(/:role_name) | Path selected | Yes          | No                          | Sign a CSR using the specified CA and don't validate its attributes against a role.                                                  | `vault path-help ejbca/issuer/example/sign-verbatim` |

The following example issues a certificate using the `example-dot-com` role:
```shell
vault write ejbca/issue/example-dot-com \
    common_name="example.com" \
    alt_names="*.example.com" \
    format="pem_bundle" \
    account_binding_id="abc123"
```

### Revoke Paths
The following path can be used to revoke certificates. Either the `serial_number` or `certificate` parameter is required.

| Path            | Required Parameters                                              | Description                                                              | Help Path                               |
|-----------------|------------------------------------------------------------------|--------------------------------------------------------------------------|-----------------------------------------|
| revoke          | serial_number _or_ certificate PEM                               | Revokes a certificate by serial number _or_ certificate itself.          | `vault path-help ejbca/revoke`          |
| revoke-with-key | certificate private key _and_ serial_number _or_ certificate PEM | Revokes a certificate only if the user proves they have the private key. | `vault path-help ejbca/revoke-with-key` |

The following example revokes a certificate and provides the private key:
```shell
vault write ejbca/revoke-with-key \
    serial_number="62:c6:3f:13:12:39:9d:75:2c:77:db:62:bd:e2:47:3a:0b:56:de:de" \
    private_key="-----BEGIN EC PRIVATE KEY----- MHcCAQEEII1YXWvr+8i5o8QQ5I3mF/T55AGzQ8VrC2VPHa+m5MvooAoGCCqGSM49 AwEHoUQDQgAEL6+GnD6BtY3mEY2qLfGJVPP4Cx23WeGYBbvxsgz+Kh85S7Z92llx zZUn7uSYC0bvNhHJ1I4SpZNKDWKbXWMgQQ== -----END EC PRIVATE KEY-----"
```

> **Note:** The EJBCA PKI Secrets Engine cannot revoke certificates that were not issued by the EJBCA PKI Secrets Engine. That is, the certificate must exist in the Secrets Engine's backend.

### Read/List Paths
The following paths can be used to fetch CA certificates. The paths that specify a `Content-Type` cannot be consumed using the `vault` command, and must be consumed using the Vault HTTP API. Any path that uses `ca` as its root will report the default issuer/CA configured in the Config path.

| Path                   | Content-Type                      | Encoding | Response Format | Whole chain? | Help Path                                  |
|------------------------|-----------------------------------|----------|-----------------|--------------|--------------------------------------------|
| ca                     | application/pkix-cert             | DER      | DER             | false        | `vault path-help ejbca/ca`                 |
| ca/pem                 | application/pem-certificate-chain | PEM      | PEM             | true         | `vault path-help ejbca/ca/pem`             |
| cert/ca                | <none>                            | PEM      | JSON            | true         | `vault path-help ejbca/cert/ca`            |
| cert/ca/raw            | application/pkix-cert             | DER      | DER             | false        | `vault path-help ejbca/cert/ca/raw`        |
| cert/ca/raw/pem        | application/pem-certificate-chain | PEM      | PEM             | true         | `vault path-help ejbca/cert/ca/raw/pem`    |
| ca_chain               | application/pkix-cert             | PEM      | PEM             | true         | `vault path-help ejbca/ca_chain`           |
| cert/ca_chain          | <none>                            | PEM      | JSON            | true         | `vault path-help ejbca/cert/ca_chain`      |
| issuer/:issuer_ref     | <none>                            | PEM      | JSON            | true         | `vault path-help ejbca/issuer/example`     |
| issuer/:issuer_ref/pem | application/pem-certificate-chain | PEM      | PEM             | true         | `vault path-help ejbca/issuer/example/pem` |

The following paths can be used to fetch certificates.

| Path             | Content-Type                      | Encoding | Help Path                               |
|------------------|-----------------------------------|----------|-----------------------------------------|
| cert/:serial     | <none>                            | PEM      | `vault path-help ejbca/cert/123456`     |
| cert/:serial/raw | application/pkix-cert             | DER      | `vault path-help ejbca/cert/123456/raw` |
| cert/:serial/pem | application/pem-certificate-chain | PEM      | `vault path-help ejbca/cert/123456/pem` |

:pushpin: **Note:** The fetch methods will never return a private key. Private keys are only returned with the `issue` methods.

Serial numbers of certificates and revoked certificates can be found using the following paths.

| Path          | Description                                                     | Help Path                             |
|---------------|-----------------------------------------------------------------|---------------------------------------|
| certs         | Lists all certificates issued by the EJBCA PKI Secrets Engine.  | `vault path-help ejbca/certs`         |
| certs/revoked | Lists all certificates revoked by the EJBCA PKI Secrets Engine. | `vault path-help ejbca/certs/revoked` |

## Configuring End Entity Name
The `default_end_entity_name` and `end_entity_name` fields in the Config and Role paths allow you to configure how the End Entity Name is selected when issuing certificates through EJBCA. This field offers flexibility by allowing you to select different components from the Certificate Signing Request (CSR) or other contextual data as the End Entity Name.

### Configurable Options
Here are the different options you can set for `default_end_entity_name` for the Config path or `end_entity_name` for the Role path:

* **`cn`:** Uses the Common Name from the CSR's Distinguished Name.
* **`dns`:** Uses the first DNS Name from the CSR's Subject Alternative Names (SANs).
* **`uri`:** Uses the first URI from the CSR's Subject Alternative Names (SANs).
* **`ip`:** Uses the first IP Address from the CSR's Subject Alternative Names (SANs).
* **Custom Value:** Any other string will be directly used as the End Entity Name.

### Default Behavior
If the `end_entity_name` field is not explicitly set, the EJBCA Vault PKI Engine will attempt to determine the End Entity Name using the following default behavior:

* **First, it will try to use the Common Name:** It looks at the Common Name from the CSR's Distinguished Name.
* **If the Common Name is not available, it will use the first DNS Name:** It looks at the first DNS Name from the CSR's Subject Alternative Names (SANs).
* **If the DNS Name is not available, it will use the first URI:** It looks at the first URI from the CSR's Subject Alternative Names (SANs).
* **If the URI is not available, it will use the first IP Address:** It looks at the first IP Address from the CSR's Subject Alternative Names (SANs).
* **If none of the above are available:** The certificate issuance will fail.

If the Engine is unable to determine a valid End Entity Name through these steps, an error will be logged and no End Entity Name will be set.
