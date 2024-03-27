<!--EJBCA Community logo -->
<a href="https://ejbca.org">
    <img src="community-ejbca.png?raw=true)" alt="EJBCA logo" title="EJBCA" height="70" />
</a>
<!--EJBCA Enterprise logo -->
<a href="https://www.keyfactor.com/products/ejbca-enterprise/">
    <img src="keyfactor-ejbca-enterprise.png?raw=true)" alt="EJBCA logo" title="EJBCA" height="70" />
</a>

<!--- Insert the Tool Name in the main heading! --->
# EJBCA PKI Secrets Engine for HashiCorp Vault

[![Go Report Card](https://goreportcard.com/badge/github.com/Keyfactor/ejbca-vault-pki-engine)](https://goreportcard.com/report/github.com/Keyfactor/ejbca-vault-pki-engine)

<!--- Short intro here! --->
<!--- Include a description of the project/repository, the purpose of it, what problems it solves, when to use it (and not use it), etc. --->

The EJBCA PKI Secrets Engine for HashiCorp Vault enables DevOps teams to request and retrieve certificates 
from EJBCA using HashiCorp Vault, while security teams retain control over backend PKI operations.

The secrets engine is built on top of the [EJBCA REST API](https://doc.primekey.com/ejbca/ejbca-operations/ejbca-ca-concept-guide/protocols/ejbca-rest-interface) 
and uses the [EJBCA Go Client SDK](https://github.com/Keyfactor/ejbca-go-client-sdk) for programmatic access.
The EJBCA PKI Secrets Engine is a Vault plugin that replicates the built-in Vault PKI secrets engine, but processes
requests through EJBCA instead of through Vault. The plugin was designed to be swapped for the built-in Vault PKI secrets engine
with minimal changes to existing Vault configurations.

## Get Started

<!--- Insert links to instructions on how to install, configure, etc. 
Example from ejbca-cert-manager-issuer below:

* To install the tool, see [Installation](docs/install.md).
* To configure and use the tool, see: 
  * [Usage](docs/config_usage.md)
  * [Customization](docs/annotations.md)
  * [End Entity Name Selection](docs/endentitynamecustomization.md)
* To test the tool, see [Testing the Source](docs/testing.md).
--->

To get started with EJBCA PKI Secrets Engine for HashiCorp Vault, see [Getting Started](docs/getting-started.md).

### System Requirements

<!--- Insert any requirements in this section. --->
To run the EJBCA PKI Secrets Engine for HashiCorp Vault, the EJBCA REST API needs to be set up with certain endpoints. There are also requirements on certain versions of Git, Golang, EJBCA, and HashiCorp Vault. 

See the complete list in [System Requirements](docs/getting-started.md#requirements). 

## Community Support
In the [Keyfactor Community](https://www.keyfactor.com/community/), we welcome contributions. 

The Community software is open-source and community-supported, meaning that **no SLA** is applicable.

* To report a problem or suggest a new feature, go to [Issues](../../issues).
* If you want to contribute actual bug fixes or proposed enhancements, see the [Contributing Guidelines](CONTRIBUTING.md) and go to [Pull requests](../../pulls).

## Commercial Support

Commercial support is available for [EJBCA Enterprise](https://www.keyfactor.com/products/ejbca-enterprise/).

<!--- For SignServer, update to the following text and link:
Commercial support is available for [SignServer Enterprise](https://www.keyfactor.com/products/signserver-enterprise/).
--->

## License
<!--- No updates needed --->
For License information, see [LICENSE](LICENSE). 

## Related Projects
See all [Keyfactor EJBCA GitHub projects](https://github.com/orgs/Keyfactor/repositories?q=ejbca). 
