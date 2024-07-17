<h1 align="center" style="border-bottom: none">


EJBCA Vault PKI Secrets Engine

<img src="https://img.shields.io/badge/integration_status-production-3D1973?style=flat-square" alt="Integration Status: production" />
<a href="https://github.com/keyfactor/ejbca-cert-manager-issuer/releases/latest"><img src="https://img.shields.io/github/v/release/keyfactor/ejbca-cert-manager-issuer?style=flat-square" alt="Latest Release"></a>
<a href="https://ejbca.org"><img src="https://img.shields.io/badge/valid_for-ejbca_community-FF9371" alt="Valid for EJBCA Community"></a>
<a href="https://www.keyfactor.com/products/ejbca-enterprise/"><img src="https://img.shields.io/badge/valid_for-ejbca_enterprise-5F61FF" alt="Valid for EJBCA Enterprise"></a>
<a href="https://goreportcard.com/report/github.com/keyfactor/ejbca-cert-manager-issuer"><img src="https://goreportcard.com/badge/github.com/keyfactor/ejbca-cert-manager-issuer" alt="Go Report Card"></a>
<a href="https://img.shields.io/badge/License-Apache%202.0-blue.svg"><img src="https://img.shields.io/badge/License-Apache%202.0-blue.svg" alt="License Apache 2.0"></a>



</h1>

<p align="center">
  <!-- TOC -->
  <a href="#support">
    <b>Support</b>
  </a>
  ·
  <a href="#get-started">
    <b>Get Started</b>
  </a>
  ·
  <a href="#license">
    <b>License</b>
  </a>
  ·
  <a href="https://github.com/orgs/Keyfactor/repositories?q=ejbca">
    <b>Related Integrations</b>
  </a>
</p>

## Overview

The EJBCA PKI Secrets Engine for HashiCorp Vault enables DevOps teams to request and retrieve certificates 
from EJBCA using HashiCorp Vault, while security teams retain control over backend PKI operations.

The secrets engine is built on top of the [EJBCA REST API](https://doc.primekey.com/ejbca/ejbca-operations/ejbca-ca-concept-guide/protocols/ejbca-rest-interface) 
and uses the [EJBCA Go Client SDK](https://github.com/Keyfactor/ejbca-go-client-sdk) for programmatic access.
The EJBCA PKI Secrets Engine is a Vault plugin that replicates the built-in Vault PKI secrets engine, but processes
requests through EJBCA instead of through Vault. The plugin was designed to be swapped for the built-in Vault PKI secrets engine
with minimal changes to existing Vault configurations.



## Support

In the [Keyfactor Community](https://www.keyfactor.com/community/), we welcome contributions. Keyfactor Community software is open-source and community-supported, meaning that **no SLA** is applicable. Keyfactor will address issues as resources become available.

* To report a problem or suggest a new feature, go to [Issues](../../issues).
* If you want to contribute bug fixes or proposed enhancements, see the [Contributing Guidelines](CONTRIBUTING.md) and create a [Pull request](../../pulls).

> Commercial support is available for [EJBCA Enterprise](https://www.keyfactor.com/products/ejbca-enterprise/) customers, who may request escalation by opening up a support ticket through their Keyfactor representative.

## Requirements

* [EJBCA](https://ejbca.org) (>= 7.10)
* [Terraform](https://www.terraform.io/downloads) (>= 1.0)
* [Go](https://go.dev/doc/install) (1.22.3)
* [GNU Make](https://www.gnu.org/software/make/)

### To build
* [Git](https://git-scm.com/)
* [Golang](https://golang.org/) >= v1.19

### To use
* [EJBCA](https://www.keyfactor.com/products/ejbca-enterprise/) >= v7.7
* [HashiCorp Vault](https://www.vaultproject.io/) >= v1.11.0



## Getting Started

To get started with EJBCA PKI Secrets Engine for HashiCorp Vault, see [Getting Started](docs/getting-started.md).



## License
For license information, see [LICENSE](LICENSE). 

## Related Projects
See all [Keyfactor EJBCA GitHub projects](https://github.com/orgs/Keyfactor/repositories?q=ejbca). 