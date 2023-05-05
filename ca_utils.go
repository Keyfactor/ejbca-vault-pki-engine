package ejbca_vault_pki_engine

import (
	"context"
	"crypto/x509"
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
	Certificate  string   `json:"certificate"`
	CAChain      []string `json:"ca_chain"`
	SerialNumber string   `json:"serial_number"`
}

func (c *caStorageContext) putCaEntry(caName string, entry caEntry) error {
	storageEntry, err := logical.StorageEntryJSON(issuerPath+caName, entry)
	if err != nil {
		return err
	}

	return c.storageContext.Storage.Put(c.storageContext.Context, storageEntry)
}

func (c *caStorageContext) fetchCaBundle(caName string) (*certutil.CAInfoBundle, error) {
	storageEntry, err := c.storageContext.Storage.Get(c.storageContext.Context, "config/issuer/"+caName)
	if err != nil {
		return nil, errutil.InternalError{Err: fmt.Sprintf("error fetching CA certificate: %s", err)}
	}

	var parsedStorageEntry caEntry

	if storageEntry != nil && storageEntry.Value != nil && len(storageEntry.Value) > 0 {
		err = storageEntry.DecodeJSON(&parsedStorageEntry)
		if err != nil {
			return nil, errutil.InternalError{Err: fmt.Sprintf("unable to decode ca entry: %v", err)}
		}
	} else {
		// TODO retrieve CA certificate from EJBCA if not found in vault

		client, err := c.storageContext.getClient()
		if err != nil {
			return nil, err
		}
		// Get a list of all CAs
		caList, _, err := client.V1CaApi.ListCas(c.storageContext.Context).Execute()
		if err != nil {
			return nil, err
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
		chain, err := getCaChain(c.storageContext.Context, client, caSubjectDN)
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
			Certificate:  chainList[0],
			CAChain:      chainList[1:],
			SerialNumber: chain[0].SerialNumber.String(),
		}
		err = c.putCaEntry(caName, parsedStorageEntry)
		if err != nil {
			return nil, err
		}
	}

	if parsedStorageEntry.Certificate == "" {
		return nil, errutil.InternalError{Err: fmt.Sprintf("returned CA certificate bytes were empty")}
	}

	certBundle := &certutil.CertBundle{
		Certificate:  parsedStorageEntry.Certificate,
		CAChain:      parsedStorageEntry.CAChain,
		SerialNumber: parsedStorageEntry.SerialNumber,
	}

	parsedBundle, err := certBundle.ToParsedCertBundle()
	if err != nil {
		return nil, errutil.InternalError{Err: fmt.Sprintf("error parsing ca cert bundle: %s", err)}
	}

	if parsedBundle.Certificate == nil {
		return nil, errutil.InternalError{Err: "stored CA information not able to be parsed"}
	}

	caInfo := &certutil.CAInfoBundle{
		ParsedCertBundle: *parsedBundle,
	}

	return caInfo, nil
}

func (b *caResponseBuilder) getPemEncoder() func(*certutil.CAInfoBundle) []string {
	return func(caBundle *certutil.CAInfoBundle) []string {
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
	return func(caBundle *certutil.CAInfoBundle) []string {
		return []string{string(caBundle.Certificate.Raw)}
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

// Path            |      Content-Type                    | Encoding  | Format                | Whole chain?
// --------------- | ------------------------------------ | --------- | --------------------- | ------------
// ca	           | application/pkix-cert                | DER 	  | DER 				  | false
// ca/pem          | application/pem-certificate-chain    | PEM 	  | PEM 				  | true
// cert/ca         | <none> 							  | PEM 	  | JSON 				  | true
// cert/ca/raw     | application/pkix-cert                | DER 	  | DER 				  | false
// cert/ca/raw/pem | application/pem-certificate-chain    | PEM 	  | PEM 				  | true
// ca_chain		   | application/pkix-cert                | PEM 	  | PEM 				  | true
// cert/ca_chain   | <none>                               | PEM 	  | JSON 				  | true

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

	// If path is not JSON response, initialize response object as failure
	b.response = &logical.Response{Data: map[string]interface{}{}}
	if !b.isJsonResponse {
		b.response.Data[logical.HTTPRawBody] = []byte{}
		b.response.Data[logical.HTTPStatusCode] = http.StatusNoContent
	}

	b.caName = defaultCaName

	return b
}

// Path                     |      Content-Type                    | Encoding  | Format                | Whole chain?
// ------------------------ | ------------------------------------ | --------- | --------------------- | ------------
// issuer/:issuer_ref/json  | <none> 							   | PEM 	   | JSON 		    	   | true
// issuer/:issuer_ref/pem   | application/pem-certificate-chain    | PEM       | PEM 				   | true
// issuer/:issuer_ref/der   | application/pkix-cert                | DER 	   | DER 				   | false
// issuer/:issuer_ref       | <none>                               | PEM       | PEM 				   | true

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

	if strings.HasSuffix(path, "/json") {
		b.isJsonResponse = true
		b.includeChain = true
		b.encoder = b.getPemEncoder()
		b.customJsonSchema = map[string]string{
			"issuer_name": issuerName,
			"issuer_id":   issuerName,
		}
	} else if strings.HasSuffix(path, "/pem") {
		b.isJsonResponse = false
		b.contentType = "application/pem-certificate-chain"
		b.includeChain = true
		b.encoder = b.getPemEncoder()
	} else if strings.HasSuffix(path, "/der") {
		b.isJsonResponse = false
		b.contentType = "application/pkix-cert"
		b.includeChain = false
		b.encoder = b.getDerEncoder()
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
	}

	b.caName = issuerName

	return b
}

func (b *caResponseBuilder) Build() (*logical.Response, error) {
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
		// If path is JSON response, initialize response object as success and populate with encoded CA bundle
		if len(encodedCa) == 0 {
			return logical.ErrorResponse("No default CA found"), nil
		}

		b.response.Data["certificate"] = encodedCa[0]
		b.response.Data["ca_chain"] = []string{}
		for _, cert := range encodedCa[1:] {
			b.response.Data["ca_chain"] = append(b.response.Data["ca_chain"].([]string), cert)
		}
		for key, value := range b.customJsonSchema {
			b.response.Data[key] = value
		}
	} else {
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

func getCaChain(ctx context.Context, client *ejbcaClient, issuerDn string) ([]*x509.Certificate, error) {
	caResp, err := client.V1CaApi.GetCertificateAsPem(ctx, issuerDn).Execute()
	if err != nil {
		return nil, err
	}

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
