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
* [Golang](https://golang.org/) >= v1.22

## To use
* [EJBCA](https://www.keyfactor.com/products/ejbca-enterprise/) >= v7.7
* [HashiCorp Vault](https://www.vaultproject.io/) >= v1.11.0

# Badges

[![Valid for EJBCA Community](https://img.shields.io/badge/valid_for-ejbca_community-FF9371)](https://ejbca.org)
[![Valid for EJBCA Enterprise](https://img.shields.io/badge/valid_for-ejbca_enterprise-5F61FF)](https://www.keyfactor.com/products/ejbca-enterprise/)
[![Go Report Card](https://goreportcard.com/badge/github.com/keyfactor/ejbca-vault-pki-engine)](https://goreportcard.com/report/github.com/keyfactor/ejbca-vault-pki-engine)

# Getting Started

To get started with EJBCA PKI Secrets Engine for HashiCorp Vault, see [Getting Started](docs/getting-started.md).
