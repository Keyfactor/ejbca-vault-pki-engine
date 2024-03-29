/*
Copyright 2024 Keyfactor
Licensed under the Apache License, Version 2.0 (the "License"); you may
not use this file except in compliance with the License.  You may obtain a
copy of the License at http://www.apache.org/licenses/LICENSE-2.0.  Unless
required by applicable law or agreed to in writing, software distributed
under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES
OR CONDITIONS OF ANY KIND, either express or implied. See the License for
thespecific language governing permissions and limitations under the
License.
*/
package ejbca_vault_pki_engine

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	"github.com/Keyfactor/ejbca-go-client-sdk/api/ejbca"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/helper/errutil"
)

type ejbcaClient struct {
	*ejbca.APIClient
}

func newClient(config *ejbcaConfig) (*ejbcaClient, error) {
	logger := hclog.New(&hclog.LoggerOptions{})

	// Validate the configuration
	if config == nil {
		return nil, errors.New("client configuration was nil")
	}

	if config.Hostname == "" {
		return nil, errors.New("client hostname was not defined")
	}

	if config.ClientCert == "" {
		return nil, errors.New("client cert was not defined")
	}

	if config.ClientKey == "" {
		return nil, errors.New("client key was not defined")
	}

	logger.Debug("Creating EJBCA client")

	// Construct EJBCA configuration object
	configuration := ejbca.NewConfiguration()
	configuration.Host = config.Hostname
	logger.Debug(fmt.Sprintf("Setting hostname to %s", config.Hostname))

	// Decode the PEM encoded client cert and key using Go standard libraries to ensure they are valid
	certKeyBytes := []byte(config.ClientCert + "\n" + config.ClientKey)
	clientCertBlock, privKeyBlock := decodePEMBytes(certKeyBytes)
	logger.Debug(fmt.Sprintf("Found client certificate with %d PEM blocks", len(clientCertBlock)))

	if len(clientCertBlock) == 0 {
		return nil, errors.New("client certificate contains data but a PEM structure could not be decoded - please check the format of your client certificate and key")
	}

	// Create a TLS certificate object
	tlsCert, err := tls.X509KeyPair(pem.EncodeToMemory(clientCertBlock[0]), pem.EncodeToMemory(privKeyBlock))
	if err != nil {
		return nil, err
	}

	// Set the TLS configuration
	configuration.SetClientCertificate(&tlsCert)

	if config.CaCert != "" {
		caChainBlocks, _ := decodePEMBytes([]byte(config.CaCert))

		var caChain []*x509.Certificate
		for _, block := range caChainBlocks {
			// Parse the PEM block into an x509 certificate
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("failed to parse certificate from provided CA chain: %v", err)
			}

			caChain = append(caChain, cert)
		}

		configuration.SetCaCertificates(caChain)
	}

	apiClient, err := ejbca.NewAPIClient(configuration)
	if err != nil {
		return nil, err
	}

	return &ejbcaClient{apiClient}, nil
}

func (e *ejbcaClient) createErrorFromEjbcaErr(b *ejbcaBackend, detail string, err error) error {
	logger := b.Logger().Named("ejbcaClient.createErrorFromEjbcaErr")
	if err == nil {
		return nil
	}
	errString := fmt.Sprintf("%s - %s", detail, err.Error())

	bodyError, ok := err.(*ejbca.GenericOpenAPIError)
	if ok {
		errString += fmt.Sprintf(" - EJBCA API returned error %s", bodyError.Body())
	}

	logger.Error("EJBCA returned an error!", "error", errString)

	return errutil.InternalError{Err: errString}
}

func decodePEMBytes(buf []byte) ([]*pem.Block, *pem.Block) {
	logger := hclog.New(&hclog.LoggerOptions{})
	var privKey *pem.Block
	var certificates []*pem.Block
	var block *pem.Block
	for {
		block, buf = pem.Decode(buf)
		if block == nil {
			break
		} else if strings.Contains(block.Type, "PRIVATE KEY") {
			logger.Trace("Found private key in PEM block")
			privKey = block
		} else {
			logger.Trace("Found certificate in PEM block")
			certificates = append(certificates, block)
		}
	}
	return certificates, privKey
}
