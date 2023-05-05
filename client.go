package ejbca_vault_pki_engine

import (
	"crypto/tls"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/Keyfactor/ejbca-go-client-sdk/api/ejbca"
	"strings"
)

type ejbcaClient struct {
	*ejbca.APIClient
}

func newClient(config *ejbcaConfig) (*ejbcaClient, error) {
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

	// Construct EJBCA configuration object
	configuration := ejbca.NewConfiguration()
	configuration.Host = config.Hostname

	// Decode the PEM encoded client cert and key using Go standard libraries to ensure they are valid
	certKeyBytes := []byte(config.ClientCert + config.ClientKey)
	clientCertBlock, privKeyBlock := decodePEMBytes(certKeyBytes)

	// Create a TLS certificate object
	tlsCert, err := tls.X509KeyPair(pem.EncodeToMemory(clientCertBlock[0]), pem.EncodeToMemory(privKeyBlock))
	if err != nil {
		return nil, err
	}

	// Set the TLS configuration
	configuration.SetClientCertificate(&tlsCert)

	apiClient, err := ejbca.NewAPIClient(configuration)
	if err != nil {
		return nil, err
	}

	return &ejbcaClient{apiClient}, nil
}

func (e *ejbcaClient) createErrorFromEjbcaErr(b *ejbcaBackend, operationString string, err error) error {
	if err == nil {
		return nil
	}
	errString := fmt.Sprintf("Failed to %s - %s", operationString, err.Error())

	bodyError, ok := err.(*ejbca.GenericOpenAPIError)
	if ok {
		errString += fmt.Sprintf(" - EJBCA API returned error %s", bodyError.Body())
	}

	b.Logger().Error(errString)

	return fmt.Errorf(errString)
}

func decodePEMBytes(buf []byte) ([]*pem.Block, *pem.Block) {
	var privKey *pem.Block
	var certificates []*pem.Block
	var block *pem.Block
	for {
		block, buf = pem.Decode(buf)
		if block == nil {
			break
		} else if strings.Contains(block.Type, "PRIVATE KEY") {
			privKey = block
		} else {
			certificates = append(certificates, block)
		}
	}
	return certificates, privKey
}
