/*
Copyright 2023 Keyfactor
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
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"github.com/hashicorp/vault/sdk/helper/certutil"
	"github.com/hashicorp/vault/sdk/helper/errutil"
	"github.com/hashicorp/vault/sdk/logical"
	"io"
	"net/http"
	"strings"
)

const (
	issuerPath = "config/issuer/"
)

type caEntry struct {
	CaCertificate string   `json:"ca_certificate"`
	CAChain       []string `json:"ca_chain"`
}

func (c *caStorageContext) resolveIssuerReference(caName string) error {
    logger := c.storageContext.Backend.Logger().Named("caStorageContext.resolveIssuerReference")
    logger.Debug("Verifying that CA exists in EJBCA", "caName", caName)

	client, err := c.storageContext.getClient()
	if err != nil {
		return err
	}
	// Get a list of all CAs
    logger.Trace("Fetching CA list from EJBCA")
	caList, _, err := client.V1CaApi.ListCas(c.storageContext.Context).Execute()
	if err != nil {
        return client.createErrorFromEjbcaErr(c.storageContext.Backend, "Failed to fetch CA list from EJBCA", err)
	}

	for _, ca := range caList.GetCertificateAuthorities() {
		if ca.GetName() == caName {
            logger.Trace(fmt.Sprintf("CA called %s exists in EJBCA", caName))
			return nil
		}
	}

	return fmt.Errorf("CA %s not found", caName)
}

func (c *caStorageContext) putCaEntry(caName string, entry caEntry) error {
	storageEntry, err := logical.StorageEntryJSON(issuerPath+caName, entry)
	if err != nil {
		return err
	}

    c.storageContext.Backend.Logger().Debug("Storing CA entry in EJBCA Vault PKI Engine", "caName", caName)
	return c.storageContext.Storage.Put(c.storageContext.Context, storageEntry)
}

func (c *caStorageContext) fetchCaBundle(caName string) (*certutil.CAInfoBundle, error) {
    logger := c.storageContext.Backend.Logger().Named("caStorageContext.fetchCaBundle")
    logger.Debug("Fetching CA bundle", "caName", caName)

	storageEntry, err := c.storageContext.Storage.Get(c.storageContext.Context, issuerPath+caName)
	if err != nil {
		return nil, errutil.InternalError{Err: fmt.Sprintf("error fetching CA certificate: %s", err)}
	}

	var parsedStorageEntry caEntry

	if storageEntry != nil && storageEntry.Value != nil && len(storageEntry.Value) > 0 {
        logger.Trace("CA entry found in storage")
		err = storageEntry.DecodeJSON(&parsedStorageEntry)
		if err != nil {
			return nil, errutil.InternalError{Err: fmt.Sprintf("unable to decode ca entry: %v", err)}
		}
	} else {
        logger.Trace("CA entry not found in storage, fetching from EJBCA")

		client, err := c.storageContext.getClient()
		if err != nil {
			return nil, err
		}

        logger.Trace("Fetching CAs from EJBCA")
		caList, _, err := client.V1CaApi.ListCas(c.storageContext.Context).Execute()
		if err != nil {
            return nil, client.createErrorFromEjbcaErr(c.storageContext.Backend, "Failed to fetch CA list from EJBCA", err)
        }

		// Find the subject DN of the CA we're looking for
		var caSubjectDN string
		for _, ca := range caList.GetCertificateAuthorities() {
			if ca.GetName() == caName {
				caSubjectDN = ca.GetSubjectDn()
				break
			}
		}

		// Then, download the certificate chain
        logger.Trace(fmt.Sprintf("Fetching CA chain for CA called %q with DN %q", caName, caSubjectDN))
		chain, err := c.getCaChain(c.storageContext.Context, client, caSubjectDN)
		if err != nil {
			return nil, err
		}

		// Compile the chain into a list of PEM-encoded certificates
		var chainList []string
		for _, cert := range chain {
			block := pem.Block{
				Type:  "CERTIFICATE",
				Bytes: cert.Raw,
			}
			chainList = append(chainList, strings.TrimSpace(string(pem.EncodeToMemory(&block))))
		}

		// Store the CA certificate and chain in Vault

		parsedStorageEntry = caEntry{
			//SerialNumber:  certutil.GetHexFormatted(chain[0].SerialNumber.Bytes(), ":"),
			CaCertificate: chainList[0],
			CAChain:       chainList[1:],
		}

        logger.Trace("Storing CA entry in storage")
		err = c.putCaEntry(caName, parsedStorageEntry)
		if err != nil {
			return nil, err
		}
	}

	if parsedStorageEntry.CaCertificate == "" {
		return nil, errutil.InternalError{Err: "returned CA certificate bytes were empty"}
	}

	certBundle := &certutil.CertBundle{
		//SerialNumber: parsedStorageEntry.SerialNumber,
		Certificate: parsedStorageEntry.CaCertificate,
		CAChain:     parsedStorageEntry.CAChain,
	}

	parsedBundle, err := certBundle.ToParsedCertBundle()
	if err != nil {
		return nil, errutil.InternalError{Err: fmt.Sprintf("error parsing ca cert bundle: %s", err)}
	}

	caInfo := &certutil.CAInfoBundle{
		ParsedCertBundle: *parsedBundle,
	}

	return caInfo, nil
}

func (b *caResponseBuilder) getPemEncoder() func(*certutil.CAInfoBundle) []string {
    logger := b.sc.Backend.Logger().Named("caResponseBuilder.pemEncoder")
	return func(caBundle *certutil.CAInfoBundle) []string {
        logger.Trace("PEM encoding CA bundle")

		if b.includeChain {
			var chainList []string
			rawChain := caBundle.GetFullChain()
			for _, cert := range rawChain {
				block := pem.Block{
					Type:  "CERTIFICATE",
					Bytes: cert.Bytes,
				}
				chainList = append(chainList, strings.TrimSpace(string(pem.EncodeToMemory(&block))))
			}
			return chainList
		} else {
			block := pem.Block{
				Type:  "CERTIFICATE",
				Bytes: caBundle.Certificate.Raw,
			}
			return []string{strings.TrimSpace(string(pem.EncodeToMemory(&block)))}
		}
	}
}

func (b *caResponseBuilder) getDerEncoder() func(*certutil.CAInfoBundle) []string {
    logger := b.sc.Backend.Logger().Named("caResponseBuilder.derEncoder")
	return func(caBundle *certutil.CAInfoBundle) []string {
        logger.Trace("DER encoding CA bundle")

		var derStringList []string
		if b.includeChain {
			rawChain := caBundle.GetFullChain()
			for _, cert := range rawChain {
				derStringList = append(derStringList, base64.StdEncoding.EncodeToString(cert.Bytes))
			}
		} else {
			derStringList = append(derStringList, base64.StdEncoding.EncodeToString(caBundle.Certificate.Raw))
		}
		return derStringList
	}
}

type caResponseBuilder struct {
	sc               *storageContext
	isJsonResponse   bool
	contentType      string
	includeChain     bool
	encoder          func(*certutil.CAInfoBundle) []string
	response         *logical.Response
	caName           string
	customJsonSchema map[string]string
}

type caResponseHelper struct {
	isHttpResponse  bool
	httpContentType string
	includeChain    bool
	encoder         func(*certutil.CAInfoBundle) []string
}

func (b *caResponseBuilder) Config(sc *storageContext, path string) *caResponseBuilder {
	b.sc = sc
	// Map path to expected response behavior
	responseMap := map[string]caResponseHelper{
		"ca":              {true, "application/pkix-cert", false, b.getDerEncoder()},
		"ca/pem":          {true, "application/pem-certificate-chain", true, b.getPemEncoder()},
		"cert/ca":         {false, "", true, b.getPemEncoder()},
		"cert/ca/raw":     {true, "application/pkix-cert", false, b.getDerEncoder()},
		"cert/ca/raw/pem": {true, "application/pem-certificate-chain", true, b.getPemEncoder()},
		"ca_chain":        {true, "application/pkix-cert", true, b.getPemEncoder()},
		"cert/ca_chain":   {false, "", true, b.getPemEncoder()},
	}

	responseConfig := responseMap[path]
	b.isJsonResponse = !responseConfig.isHttpResponse
	b.contentType = responseConfig.httpContentType
	b.includeChain = responseConfig.includeChain
	b.encoder = responseConfig.encoder

    b.sc.Backend.Logger().Debug("Configuring CA response builder", "path", path, "isJsonResponse", b.isJsonResponse, "contentType", b.contentType, "includeChain", b.includeChain, "caName", b.caName)

	// If path is not JSON response, initialize response object as failure
	b.response = &logical.Response{Data: map[string]interface{}{}}
	if !b.isJsonResponse {
		b.response.Data[logical.HTTPRawBody] = []byte{}
		b.response.Data[logical.HTTPStatusCode] = http.StatusNoContent
	}

    b.sc.Backend.Logger().Trace("CA Path detected, fetching default CA [setting caName to defaultCaName]", "defaultCaName", defaultCaName)
	b.caName = defaultCaName

	return b
}

// The /pki/issuer/:issuer_ref/json endpoint must return the following JSON structure:
// {
//   "certificate": "<PEM-encoded CA certificate>",
//   "ca_chain": ["<PEM-encoded CA certificate>", "<PEM-encoded intermediate CA certificate>", ...],
//   "issuer_id": "<issuer_ref>",
//   "issuer_name": "<issuer_name>",
// }

// The /pki/issuer/:issuer_ref endpoint must return the following JSON structure:
// {
//     "ca_chain": [
//         "-----BEGIN CERTIFICATE-----\nMIIDFDCCAfygAwIBAgIUXgxy54mKooz5soqQoRINazH/3pQwDQYJKoZIhvcNAQEL\n...",
//         "-----BEGIN CERTIFICATE-----\nMIIDFTCCAf2gAwIBAgIUUo/qwLm5AyqUWqFHw1MlgwUtS/kwDQYJKoZIhvcNAQEL\n..."
//     ],
//     "certificate": "-----BEGIN CERTIFICATE-----\nMIIDFDCCAfygAwIBAgIUXgxy54mKooz5soqQoRINazH/3pQwDQYJKoZIhvcNAQEL\n...",
//     "issuer_id": "7545992c-1910-0898-9e64-d575549fbe9c",
//     "issuer_name": "root-x1",
//     "key_id": "baadd98d-ec5a-66ac-06b7-dfc91c02c9cf",
//     "leaf_not_after_behavior": "truncate",
//     "manual_chain": null,
//     "usage": "read-only,issuing-certificates,crl-signing,ocsp-signing"
// }

func (b *caResponseBuilder) IssuerConfig(sc *storageContext, path string, issuerName string) *caResponseBuilder {
	b.sc = sc
    logger := b.sc.Backend.Logger().Named("caResponseBuilder.IssuerConfig")

	if strings.HasSuffix(path, "/json") {
		b.isJsonResponse = true
		b.includeChain = true
		b.encoder = b.getPemEncoder()
		b.customJsonSchema = map[string]string{
			"issuer_name": issuerName,
			"issuer_id":   issuerName,
		}
        logger.Trace("Configuring CA response builder for JSON response", "path", path, "isJsonResponse", b.isJsonResponse, "includeChain", b.includeChain, "encoder", "PEM", "customJsonSchema", b.customJsonSchema)
	} else if strings.HasSuffix(path, "/pem") {
		b.isJsonResponse = false
		b.contentType = "application/pem-certificate-chain"
		b.includeChain = true
		b.encoder = b.getPemEncoder()
        logger.Trace("Configuring CA response builder for PEM response", "path", path, "isJsonResponse", b.isJsonResponse, "includeChain", b.includeChain, "encoder", "PEM")
	} else if strings.HasSuffix(path, "/der") {
		b.isJsonResponse = false
		b.contentType = "application/pkix-cert"
		b.includeChain = false
		b.encoder = b.getDerEncoder()
        logger.Trace("Configuring CA response builder for DER response", "path", path, "isJsonResponse", b.isJsonResponse, "includeChain", b.includeChain, "encoder", "DER")
	} else {
		b.isJsonResponse = true
		b.includeChain = true
		b.encoder = b.getPemEncoder()
		b.customJsonSchema = map[string]string{
			"issuer_name":             issuerName,
			"issuer_id":               issuerName,
			"leaf_not_after_behavior": "truncate",
			"manual_chain":            "null",
			"usage":                   "read-only,issuing-certificates,crl-signing,ocsp-signing",
		}
        logger.Trace("Configuring CA response builder for JSON response", "path", path, "isJsonResponse", b.isJsonResponse, "includeChain", b.includeChain, "encoder", "PEM", "customJsonSchema", b.customJsonSchema)
	}

	// If path is not JSON response, initialize response object as failure
	b.response = &logical.Response{Data: map[string]interface{}{}}
	if !b.isJsonResponse {
		b.response.Data[logical.HTTPRawBody] = []byte{}
		b.response.Data[logical.HTTPStatusCode] = http.StatusNoContent
	}

	b.caName = issuerName

	return b
}

func (b *caResponseBuilder) Build() (*logical.Response, error) {
    logger := b.sc.Backend.Logger().Named("caResponseBuilder.Build")
    logger.Debug("Building CA response", "caName", b.caName, "isJsonResponse", b.isJsonResponse, "contentType", b.contentType, "includeChain", b.includeChain, "encoder", "PEM", "customJsonSchema", b.customJsonSchema)

	// Get CA bundle
	caBundle, err := b.sc.CA().fetchCaBundle(b.caName)
	if err != nil {
		switch err.(type) {
		case errutil.UserError:
			return logical.ErrorResponse(err.Error()), nil
		default:
			// Only return error if path is JSON response. Otherwise, response is already initialized as failure.
			if b.isJsonResponse {
				return nil, err
			} else {
				return b.response, nil
			}
		}
	}

	// Encode CA bundle
	encodedCa := b.encoder(caBundle)
	if b.isJsonResponse {
        logger.Trace("Building JSON response")
		// If path is JSON response, initialize response object as success and populate with encoded CA bundle
		if len(encodedCa) == 0 {
			return logical.ErrorResponse("No default CA found"), nil
		}

		b.response.Data["certificate"] = encodedCa[0]
		var chain []string
        chain = append(chain, encodedCa[1:]...)
		b.response.Data["ca_chain"] = chain
		for key, value := range b.customJsonSchema {
			b.response.Data[key] = value
		}
	} else {
        logger.Trace("Building HTTP response")
		// If path is not JSON response, populate response object with encoded CA bundle
		if len(encodedCa) == 0 {
			return b.response, nil
		}
		b.response.Data[logical.HTTPContentType] = b.contentType
		b.response.Data[logical.HTTPRawBody] = []byte(strings.Join(encodedCa, "\n"))
		b.response.Data[logical.HTTPStatusCode] = http.StatusOK
	}

	return b.response, nil
}

func (c *caStorageContext) getCaChain(ctx context.Context, client *ejbcaClient, issuerDn string) ([]*x509.Certificate, error) {
    logger := c.storageContext.Backend.Logger().Named("caStorageContext.getCaChain")
	logger.Debug("Fetching CA chain from EJBCA", "issuer_dn", issuerDn)

	caResp, err := client.V1CaApi.GetCertificateAsPem(ctx, issuerDn).Execute()
	if err != nil {
        return nil, client.createErrorFromEjbcaErr(c.storageContext.Backend, "Failed to fetch CA list from EJBCA", err)
	}

	// Read all bytes from response body
	encodedBytes, err := io.ReadAll(caResp.Body) // EJBCA returns CA chain as a single PEM file
	if err != nil {
		return nil, err
	}

	// Decode PEM file into a slice of der bytes
	var block *pem.Block
	var derBytes []byte
	for {
		block, encodedBytes = pem.Decode(encodedBytes)
		if block == nil {
			break
		}
		derBytes = append(derBytes, block.Bytes...)
	}

	certificates, err := x509.ParseCertificates(derBytes)
	if err != nil {
		return nil, err
	}

	return certificates, nil
}
