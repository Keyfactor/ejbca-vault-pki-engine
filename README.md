# EJBCA PKI Secrets Engine for HashiCorp Vault

[![Go Report Card](https://goreportcard.com/badge/github.com/Keyfactor/ejbca-k8s-csr-signer)](https://goreportcard.com/report/github.com/Keyfactor/ejbca-k8s-csr-signer)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://img.shields.io/badge/License-Apache%202.0-blue.svg)

The EJBCA PKI Secrets Engine for HashiCorp Vault enables DevOps teams to request and retrieve certificates 
from EJBCA using HashiCorp Vault, while security teams retain control over backend PKI operations.

The secrets engine is built on top of the [EJBCA REST API](https://doc.primekey.com/ejbca/ejbca-operations/ejbca-ca-concept-guide/protocols/ejbca-rest-interface) 
and uses the [EJBCA Go Client SDK](https://github.com/Keyfactor/ejbca-go-client-sdk) for programmatic access.
The EJBCA PKI Secrets Engine is a Vault plugin that replicates the built-in Vault PKI secrets engine, but processes
requests through EJBCA instead of through Vault. The plugin was designed to be swapped for the built-in Vault PKI secrets engine
with minimal changes to existing Vault configurations.

## Community supported
We welcome contributions.

The EJBCA PKI Secrets Engine for HashiCorp Vault is open source and community supported, meaning that there is **no SLA** applicable for these tools.

###### To report a problem or suggest a new feature, use the **[Issues](../../issues)** tab. If you want to contribute actual bug fixes or proposed enhancements, see the [contribution guidelines](https://github.com/Keyfactor/ejbca-k8s-csr-signer/blob/main/CONTRIBUTING.md) and use the **[Pull requests](../../pulls)** tab.

## Requirements
### To build
* [Git](https://git-scm.com/)
* [Golang](https://golang.org/) >= v1.19

### To use
* [Keyfactor EJBCA](https://www.keyfactor.com/products/ejbca-enterprise/) >= v7.7
* [HashiCorp Vault](https://www.vaultproject.io/) >= v1.11.0

## Installation
### From Source
Clone the repository and build the plugin.
```shell
git clone https://github.com/Keyfactor/ejbca-vault-pki-engine.git
cd ejbca-vault-pki-engine
```

Build the plugin for your platform.
```shell
go build -o ejbca cmd/ejbca-pki/main.go
````

Calculate the SHA256 checksum of the plugin.
```shell
SHA256=$(sha256sum ejbca | cut -d ' ' -f1)
```

### From GitHub Release
Download and extract the latest release for your platform.
```shell
OS=$(go env GOOS); ARCH=$(go env GOARCH); curl -L -o ejbca.tar.gz https://github.com/Keyfactor/ejbca-vault-pki-engine/releases/latest/download/ejbca-vault-pki-engine-$OS-$ARCH.tar.gz
tar xzf ejbca.tar.gz
sudo mv ejbca-vault-pki-engine </path/to/vault/plugins>
```

Register the plugin with Vault.
```shell
vault plugin register -sha256=$SHA256 secret ejbca
```

Enable the plugin.
```shell
vault secrets enable -path=ejbca -plugin-name=ejbca plugin
```

## Configuration
Before using the EJBCA PKI Secrets Engine, you must configure it by providing the following information:
- EJBCA Hostname
- Client Certificate
- Client Private Key
- Default CA Certificate (used as `issuer_ref` if not configured in role)
- Default End Entity Profile (used as `end_entity_profile_name` if not configured in role)
- Default Certificate Profile (used as `certificate_profile_name` if not configured in role)

Use the following vault command to create the `config` object:
```shell
vault write ejbca/config \
	ejbca_hostname="https://ejbca.example.com:8443/ejbca" \
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
- `account_binding_id` - EJBCA Account Binding ID.

:pushpin: **Note:** If left blank, the `end_entity_profile_name` and `certificate_profile_name` fields will default to the values configured in the `config` object.

## Path Overview
Once the EJBCA PKI Secrets Engine is configured and roles are created, you can use the following paths to issue and sign certificates,
list certificates, and revoke certificates.
### Issue/Sign Paths
The following paths can be used to issue and sign certificates. The `:role_name` parameter is required for all paths except `sign-verbatim`.
Paths that require the `:issuer_ref` parameter will use the provided name as the EJBCA CA name for certificate issuance.

:pushpin: **Note:** The `/issue` paths generate the CSR and private key on the Vault server.

| Path                                          | Issuer        | CSR required | Subject to role restriction |
|-----------------------------------------------|---------------|--------------|-----------------------------|
| sign/:role_name                               | Role selected | Yes          | Yes                         |
| issuer/:issuer_ref/sign/:role_name            | Path selected | Yes          | Yes                         |
| issue/:role_name                              | Role selected | No           | Yes                         |
| issuer/:issuer_ref/issue/:role_name           | Path selected | No           | Yes                         |
| sign-verbatim(/:role_name)                    | default       | Yes          | No                          |
| issuer/:issuer_ref/sign-verbatim(/:role_name) | Path selected | Yes          | No                          |

The following example issues a certificate using the `example-dot-com` role:
```shell
vault write ejbca/issue/example-dot-com \
    common_name="example.com" \
    alt_names="*.example.com" \
    format="pem_bundle" \
    account_binding_id="abc123"
```

:pushpin: **Note:** For more information on any of the parameters used in the above example or in the table, use the `vault path-help ejbca/<path>` command.

### Revoke Paths
The following path can be used to revoke certificates. Either the `serial_number` or `certificate` parameter is required.

| Path   | Required Parameters                | Description                                                     |
|--------|------------------------------------|-----------------------------------------------------------------|
| revoke | serial_number _or_ certificate PEM | Revokes a certificate by serial number _or_ certificate itself. |

:pushpin: **Note:** The EJBCA PKI Secrets Engine cannot revoke certificates that were not issued by the EJBCA PKI Secrets Engine.

### Fetch Paths
The following paths can be used to fetch CA certificates. The paths that specify a `Content-Type` cannot be consumed using
the `vault` command, and must be consumed using the Vault HTTP API.

| Path            | Content-Type                      | Encoding | Response Format | Whole chain? |
|-----------------|-----------------------------------|----------|-----------------|--------------|
| ca              | application/pkix-cert             | DER      | DER             | false        |
| ca/pem          | application/pem-certificate-chain | PEM      | PEM             | true         |
| cert/ca         | <none>                            | PEM      | JSON            | true         |
| cert/ca/raw     | application/pkix-cert             | DER      | DER             | false        |
| cert/ca/raw/pem | application/pem-certificate-chain | PEM      | PEM             | true         |
| ca_chain        | application/pkix-cert             | PEM      | PEM             | true         |
| cert/ca_chain   | <none>                            | PEM      | JSON            | true         |

The following paths can be used to fetch certificates.

| Path             | Content-Type                       | Encoding |
|------------------|------------------------------------|----------|
| cert/:serial     | <none>                             | PEM      |
| cert/:serial/raw | application/pkix-cert              | DER      |
| cert/:serial/pem | application/pem-certificate-chain  | PEM      |

:pushpin: **Note:** The fetch methods will never return a private key. Private keys are only returned with the `issue` methods.

Serial numbers of certificates and revoked certificates can be found using the following paths.

| Path          | Description                                                     |
|---------------|-----------------------------------------------------------------|
| certs	        | Lists all certificates issued by the EJBCA PKI Secrets Engine.  |
| certs/revoked | Lists all certificates revoked by the EJBCA PKI Secrets Engine. |