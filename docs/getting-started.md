# Get started with the EJBCA PKI Secrets Engine

## Requirements 
### EJBCA REST API Usage
The EJBCA PKI Secrets Engine requires the following API endpoints:
* `GET /v1/ca/{subject_dn}/certificate/download` - Used to fetch CA certificates and certificate chains based on the CA's subject DN.
* `GET /v1/ca` - Used to verify the CA name provided as `issuer_ref`.
* `PUT /v1/certificate/{issuer_dn}/{certificate_serial_number}/revoke` - Used to revoke certificates.
* `POST /v1/certificate/pkcs10enroll` - Used to issue certificates.
  
### System Requirements to Build
To build the EJBCA PKI Secrets Engine for HashiCorp Vault, the following requirements apply: 
* [Git](https://git-scm.com/)
* [Golang](https://golang.org/) >= v1.19

### System Requirements to Use
To use the EJBCA PKI Secrets Engine for HashiCorp Vault, the following requirements apply: 
* [Keyfactor EJBCA](https://www.keyfactor.com/products/ejbca-enterprise/) >= v7.7
* [HashiCorp Vault](https://www.vaultproject.io/) >= v1.11.0

## Installation

### Build or Download the Plugin
To install this tool, you can either build it from the source or download it from GitHub. 

#### Build from Source
Clone the repository and build the plugin.
```shell
git clone https://github.com/Keyfactor/ejbca-vault-pki-engine.git
cd ejbca-vault-pki-engine
```

Build the plugin for your platform.
```shell
go build -o ejbca-vault-pki-engine cmd/ejbca-pki/main.go
````

Calculate the SHA256 checksum of the plugin.
```shell
SHA256=$(sha256sum ejbca-vault-pki-engine | cut -d ' ' -f1)
```

#### Download from GitHub Release
Download and extract the latest release for your platform.
```shell
OS=$(go env GOOS)
ARCH=$(go env GOARCH)
curl -L https://github.com/Keyfactor/ejbca-vault-pki-engine/releases/latest/download/ejbca-vault-pki-engine-$OS-$ARCH.tar.gz
tar xzf ejbca-vault-pki-engine-$OS-$ARCH.tar.gz
```

Retrieve the SHA256 checksum of the plugin.
```shell
curl -L -o ejbca-sha256sums.txt https://github.com/Keyfactor/ejbca-vault-pki-engine/releases/latest/download/ejbca-vault-pki-engine_SHA256SUMS
SHA256=$(grep ejbca-vault-pki-engine-$OS-$ARCH.tar.gz ejbca-sha256sums.txt | cut -d ' ' -f1)
```
(the goreleaser currently calculates the hash of the whole .tar.gz file. for now, use the following command to calculate the hash of the plugin binary)
```shell
SHA256=$(sha256sum ejbca-vault-pki-engine | cut -d ' ' -f1)
````

### Install the plugin

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
