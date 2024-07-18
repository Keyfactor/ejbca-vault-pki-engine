

# EJBCA Vault PKI Secrets Engine

<img src="https://img.shields.io/badge/integration_status-production-3D1973?style=flat-square" alt="Integration Status: production" />
<a href="https://ejbca.org"><img src="https://img.shields.io/badge/valid_for-ejbca_community-FF9371" alt="Valid for EJBCA Community"></a>
<a href="https://www.keyfactor.com/products/ejbca-enterprise/"><img src="https://img.shields.io/badge/valid_for-ejbca_enterprise-5F61FF" alt="Valid for EJBCA Enterprise"></a>
<a href="https://goreportcard.com/report/github.com/keyfactor/ejbca-vault-pki-engine"><img src="https://goreportcard.com/badge/github.com/keyfactor/ejbca-vault-pki-engine" alt="Go Report Card"></a>



## Overview

The EJBCA PKI Secrets Engine for HashiCorp Vault enables DevOps teams to request and retrieve certificates 
from EJBCA using HashiCorp Vault, while security teams retain control over backend PKI operations.

The secrets engine is built on top of the [EJBCA REST API](https://doc.primekey.com/ejbca/ejbca-operations/ejbca-ca-concept-guide/protocols/ejbca-rest-interface) 
and uses the [EJBCA Go Client SDK](https://github.com/Keyfactor/ejbca-go-client-sdk) for programmatic access.
The EJBCA PKI Secrets Engine is a Vault plugin that replicates the built-in Vault PKI secrets engine, but processes
requests through EJBCA instead of through Vault. The plugin was designed to be swapped for the built-in Vault PKI secrets engine
with minimal changes to existing Vault configurations.



## Requirements

### To build
* [Git](https://git-scm.com/)
* [Golang](https://golang.org/) >= v1.22

### To use
* [EJBCA](https://www.keyfactor.com/products/ejbca-enterprise/) >= v7.7
* [HashiCorp Vault](https://www.vaultproject.io/) >= v1.11.0



## Getting Started

To get started with EJBCA PKI Secrets Engine for HashiCorp Vault, see [Getting Started](docs/getting-started.md).



## Community Support

In the [Keyfactor Community](https://www.keyfactor.com/community/), we welcome contributions. Keyfactor Community software is open-source and community-supported, meaning that **no SLA** is applicable. Keyfactor will address issues as resources become available.

* To report a problem or suggest a new feature, go to [Issues](../../issues).
* If you want to contribute bug fixes or proposed enhancements, see the [Contributing Guidelines](CONTRIBUTING.md) and create a [Pull request](../../pulls).

## Commercial Support

Commercial support is available for [EJBCA Enterprise](https://www.keyfactor.com/products/ejbca-enterprise/).

## License
For license information, see [LICENSE](LICENSE). 

## Related Projects
See all [Keyfactor EJBCA GitHub projects](https://github.com/orgs/Keyfactor/repositories?q=ejbca). 