# Overview

The EJBCA PKI Secrets Engine for HashiCorp Vault enables DevOps teams to request and retrieve certificates 
from EJBCA using HashiCorp Vault, while security teams retain control over backend PKI operations.

The secrets engine is built on top of the [EJBCA REST API](https://doc.primekey.com/ejbca/ejbca-operations/ejbca-ca-concept-guide/protocols/ejbca-rest-interface) 
and uses the [EJBCA Go Client SDK](https://github.com/Keyfactor/ejbca-go-client-sdk) for programmatic access.
The EJBCA PKI Secrets Engine is a Vault plugin that replicates the built-in Vault PKI secrets engine, but processes
requests through EJBCA instead of through Vault. The plugin was designed to be swapped for the built-in Vault PKI secrets engine
with minimal changes to existing Vault configurations.

# Requirements

## To build
* [Git](https://git-scm.com/)
* [Golang](https://golang.org/) >= v1.19

## To use
* [EJBCA](https://www.keyfactor.com/products/ejbca-enterprise/) >= v7.7
* [HashiCorp Vault](https://www.vaultproject.io/) >= v1.11.0

# Badges

<a href="https://github.com/keyfactor/ejbca-cert-manager-issuer/releases/latest"><img src="https://img.shields.io/github/v/release/keyfactor/ejbca-cert-manager-issuer?style=flat-square" alt="Latest Release"></a>
<a href="https://ejbca.org"><img src="https://img.shields.io/badge/valid_for-ejbca_community-FF9371" alt="Valid for EJBCA Community"></a>
<a href="https://www.keyfactor.com/products/ejbca-enterprise/"><img src="https://img.shields.io/badge/valid_for-ejbca_enterprise-5F61FF" alt="Valid for EJBCA Enterprise"></a>
<a href="https://goreportcard.com/report/github.com/keyfactor/ejbca-cert-manager-issuer"><img src="https://goreportcard.com/badge/github.com/keyfactor/ejbca-cert-manager-issuer" alt="Go Report Card"></a>
<a href="https://img.shields.io/badge/License-Apache%202.0-blue.svg"><img src="https://img.shields.io/badge/License-Apache%202.0-blue.svg" alt="License Apache 2.0"></a>

# Getting Started

To get started with EJBCA PKI Secrets Engine for HashiCorp Vault, see [Getting Started](docs/getting-started.md).
