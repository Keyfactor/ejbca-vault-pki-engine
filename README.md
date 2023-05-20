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
```shell
OS=$(go env GOOS); ARCH=$(go env GOARCH); curl -fsSL -o cmctl.tar.gz https://github.com/Keyfactor/ejbca-vault-pki-engine/releases/latest/download/ejbca-vault-pki-engine-$OS-$ARCH.tar.gz
tar xzf cmctl.tar.gz
sudo mv cmctl /usr/local/bin
```

Register the plugin with Vault.
```shell
vault plugin register -sha256=$SHA256 secret ejbca
```

Enable the plugin.
```shell
vault secrets enable -path=ejbca -plugin-name=ejbca plugin
```

## Path Overview
### Issue/Sign Paths
| Path                                          | Issuer        | CSR required | Subject to role restriction |
|-----------------------------------------------|---------------|--------------|-----------------------------|
| sign/:role_name                               | Role selected | Yes          | Yes                         |
| issuer/:issuer_ref/sign/:role_name            | Path selected | Yes          | Yes                         |
| issue/:role_name                              | Role selected | No           | Yes                         |
| issuer/:issuer_ref/issue/:role_name           | Path selected | No           | Yes                         |
| sign-verbatim(/:role_name)                    | default       | Yes          | No                          |
| issuer/:issuer_ref/sign-verbatim(/:role_name) | Path selected | Yes          | No                          |

### Revoke Paths
| Path   | Required Parameters                | Description                                                     |
|--------|------------------------------------|-----------------------------------------------------------------|
| revoke | serial_number _or_ certificate PEM | Revokes a certificate by serial number _or_ certificate itself. |

### Fetch Paths
| Path            | Content-Type                      | Encoding | Format | Whole chain? |
|-----------------|-----------------------------------|----------|--------|--------------|
| ca              | application/pkix-cert             | DER      | DER    | false        |
| ca/pem          | application/pem-certificate-chain | PEM      | PEM    | true         |
| cert/ca         | <none>                            | PEM      | JSON   | true         |
| cert/ca/raw     | application/pkix-cert             | DER      | DER    | false        |
| cert/ca/raw/pem | application/pem-certificate-chain | PEM      | PEM    | true         |
| ca_chain        | application/pkix-cert             | PEM      | PEM    | true         |
| cert/ca_chain   | <none>                            | PEM      | JSON   | true         |