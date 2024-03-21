# EJBCA PKI Secrets Engine for HashiCorp Vault

[![Go Report Card](https://goreportcard.com/badge/github.com/Keyfactor/ejbca-vault-pki-engine)](https://goreportcard.com/report/github.com/Keyfactor/ejbca-vault-pki-engine)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://img.shields.io/badge/License-Apache%202.0-blue.svg)

The EJBCA PKI Secrets Engine for HashiCorp Vault enables DevOps teams to request and retrieve certificates from EJBCA using HashiCorp Vault, while security teams retain control over backend PKI operations.

The secrets engine is built on top of the [EJBCA REST API](https://doc.primekey.com/ejbca/ejbca-operations/ejbca-ca-concept-guide/protocols/ejbca-rest-interface) and uses the [EJBCA Go Client SDK](https://github.com/Keyfactor/ejbca-go-client-sdk) for programmatic access. 

The EJBCA PKI Secrets Engine is a Vault plugin that replicates the built-in Vault PKI secrets engine, but processes requests through EJBCA instead of through Vault. The plugin was designed to be swapped for the built-in Vault PKI secrets engine with minimal changes to existing Vault configurations.

## EJBCA API Usage
The EJBCA PKI Secrets Engine requires the following API endpoints:
* `GET /v1/ca/{subject_dn}/certificate/download` - Used to fetch CA certificates and certificate chains based on the CA's subject DN.
* `GET /v1/ca` - Used to verify the CA name provided as `issuer_ref`.
* `PUT /v1/certificate/{issuer_dn}/{certificate_serial_number}/revoke` - Used to revoke certificates.
* `POST /v1/certificate/pkcs10enroll` - Used to issue certificates.

## Requirements
### To build
* [Git](https://git-scm.com/)
* [Golang](https://golang.org/) >= v1.19

### To use
* [Keyfactor EJBCA](https://www.keyfactor.com/products/ejbca-enterprise/) >= v7.7
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
vault write sys/plugins/catalog/secret/ejbca-vault-pki-engine sha_256=$SHA256 command="ejbca-vault-pki-engine"
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
vault write sys/plugins/catalog/secret/ejbca-vault-pki-engine sha_256=$SHA256 command="ejbca-vault-pki-engine"
```

Mount the secrets engine and choose a prefix for the path (recommended is `ejbca`).
```shell
vault secrets enable -path=ejbca -plugin-name=ejbca-vault-pki-engine plugin
```
</details>

## Configuration
Before using the EJBCA PKI Secrets Engine, you must configure it by providing the following information:
- EJBCA Hostname
- Client Certificate
- Client Private Key
- Default CA Certificate (used as `issuer_ref` if not configured in role)
- Default End Entity Profile (used as `end_entity_profile_name` if not configured in role)
- Default Certificate Profile (used as `certificate_profile_name` if not configured in role)
- Default End Entity Name - See the (configuring end entity name)[#configuring-end-entity-name] section for the possible values of this field

Use the following vault command to create the `config` object:
```shell
vault write ejbca/config \
    hostname="https://ejbca.example.com:8443/ejbca" \
    client_cert=@/path/to/client/cert.pem \
    client_key=@/path/to/client/key.pem \
    ca_cert=@/path/to/ca/cert.pem \
    end_entity_profile_name="MyEndEntityProfile" \
    certificate_profile_name="MyCertificateProfile"
```

## Roles
The EJBCA PKI Secrets Engine supports the same role configuration as the built-in Vault PKI secrets engine,
and can be used as a drop-in replacement. Use the following command to get descriptions for these fields:
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

The EJBCA PKI Secrets Engine also supports the following additional role fields:
- `end_entity_profile_name` - The name of the EJBCA End Entity Profile to use for certificate issuance.
- `certificate_profile_name` - The name of the EJBCA Certificate Profile to use for certificate issuance.
- `end_entity_name` - A value that will either be used to calculate the end entity name, or the end entity name itself. See the (configuring end entity name)[#configuring-end-entity-name] for more details.
- `account_binding_id` - EJBCA Account Binding ID.

> **Note:** If left blank, the `end_entity_profile_name`, `certificate_profile_name`, and `end_entity_name` fields will default to the values configured in the `config` object.

## Path Overview
Once the EJBCA PKI Secrets Engine is configured and roles are created, you can use the following paths to issue and sign certificates,
list certificates, and revoke certificates.
### Issue/Sign Paths
The following paths can be used to issue and sign certificates. The `:role_name` parameter is required for all paths except `sign-verbatim`. Paths that require the `:issuer_ref` parameter will use the provided name as the EJBCA CA name for certificate issuance.

> **Note:** The `/issue` paths generate the CSR and private key on the Vault server.

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

| Path   | Required Parameters                | Description                                                     | Help Path                      |
|--------|------------------------------------|-----------------------------------------------------------------|--------------------------------|
| revoke | serial_number _or_ certificate PEM | Revokes a certificate by serial number _or_ certificate itself. | `vault path-help ejbca/revoke` |

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
| certs	        | Lists all certificates issued by the EJBCA PKI Secrets Engine.  | `vault path-help ejbca/certs`         |
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

