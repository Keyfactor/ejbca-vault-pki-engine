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
	"encoding/base64"
	"encoding/pem"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/errutil"
	"github.com/hashicorp/vault/sdk/logical"
	"net/http"
	"strings"
	"time"
)

const (
	issuerRefParam = "issuer_ref"
)

var pathFetchReadSchema = map[int][]framework.Response{
	http.StatusOK: {{
		Description: "OK",
		Fields: map[string]*framework.FieldSchema{
			"certificate": {
				Type:        framework.TypeString,
				Description: `Certificate`,
				Required:    false,
			},
			"revocation_time": {
				Type:        framework.TypeString,
				Description: `Revocation time`,
				Required:    false,
			},
			"revocation_time_rfc3339": {
				Type:        framework.TypeString,
				Description: "Revocation time in RFC3339 format",
				Required:    false,
			},
			"ca_chain": {
				Type:        framework.TypeStringSlice,
				Description: `Issuing CA Chain`,
				Required:    false,
			},
		},
	}},
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

// Path                     |      Content-Type                    | Encoding  | Format                | Whole chain?
// ------------------------ | ------------------------------------ | --------- | --------------------- | ------------
// issuer/:issuer_ref/json  | <none> 							   | PEM 	   | JSON 		    	   | true
// issuer/:issuer_ref/pem   | application/pem-certificate-chain    | PEM       | PEM 				   | true
// issuer/:issuer_ref/der   | application/pkix-cert                | DER 	   | DER 				   | false
// issuer/:issuer_ref       | <none>                               | PEM       | PEM 				   | true

func pathFetch(b *ejbcaBackend) []*framework.Path {
	return []*framework.Path{
		{ // Fetch/List certs
			Pattern: "certs/?$",

			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: operationPrefixPKI,
				OperationSuffix: "certs",
			},

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.pathFetchCertList,
				},
			},

			HelpSynopsis:    pathFetchHelpSyn,
			HelpDescription: pathFetchHelpDesc,
		},
		{ // Fetch revoked certificates
			Pattern: "certs/revoked/?$",

			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: operationPrefixPKI,
				OperationSuffix: "revoked-certs",
			},

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.pathFetchRevokedCertList,
					Responses: map[int][]framework.Response{
						http.StatusOK: {{
							Description: "OK",
							Fields: map[string]*framework.FieldSchema{
								"keys": {
									Type:        framework.TypeStringSlice,
									Description: `List of Keys`,
									Required:    false,
								},
							},
						}},
					},
				},
			},

			HelpSynopsis:    pathListRevokedHelpSyn,
			HelpDescription: pathListRevokedHelpDesc,
		},
		{ // Fetch a cert by serial
			Pattern: "cert/(?P<serial>[0-9A-Fa-f-:]+)",

			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: operationPrefixPKI,
				OperationSuffix: "cert",
			},

			Fields: map[string]*framework.FieldSchema{
				"serial": {
					Type:        framework.TypeString,
					Description: "Certificate serial number, in colon- or\nhyphen-separated octal",
				},
			},

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback:  b.pathFetchCert,
					Responses: pathFetchReadSchema,
				},
			},
		},
		{ // Fetch a cert by serial, raw or pem
			Pattern: `cert/(?P<serial>[0-9A-Fa-f-:]+)/raw(/pem)?`,

			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: operationPrefixPKI,
				OperationSuffix: "cert-raw-der|cert-raw-pem",
			},

			Fields: map[string]*framework.FieldSchema{
				"serial": {
					Type:        framework.TypeString,
					Description: "Certificate serial number, in colon- or\nhyphen-separated octal",
				},
			},

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback:  b.pathFetchCertRaw,
					Responses: pathFetchReadSchema,
				},
			},
		},
		{
			Pattern: `ca(/pem)?`,

			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: operationPrefixPKI,
				OperationSuffix: "ca-der|ca-pem",
			},

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback:  b.pathFetchCA,
					Responses: pathFetchReadSchema,
				},
			},

			HelpSynopsis:    pathFetchHelpSyn,
			HelpDescription: pathFetchHelpDesc,
		},
		{
			Pattern: `(cert/)?ca_chain`,

			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: operationPrefixPKI,
				OperationSuffix: "ca-chain-pem|cert-ca-chain",
			},

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback:  b.pathFetchCA,
					Responses: pathFetchReadSchema,
				},
			},

			HelpSynopsis:    pathFetchHelpSyn,
			HelpDescription: pathFetchHelpDesc,
		},
		{ // Fetch an issuer by name
			Pattern: "issuer/" + framework.GenericNameRegex(issuerRefParam) + "$",

			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: operationPrefixPKI,
				OperationSuffix: "issuer",
			},

			Fields: map[string]*framework.FieldSchema{
				issuerRefParam: {
					Type:        framework.TypeString,
					Description: "The name of the EJBCA CA",
				},
			},

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathFetchIssuer,
					Responses: map[int][]framework.Response{
						http.StatusOK: {{
							Description: "OK",
							Fields: map[string]*framework.FieldSchema{
								"issuer_id": {
									Type:        framework.TypeString,
									Description: `Issuer Id`,
									Required:    false,
								},
								"issuer_name": {
									Type:        framework.TypeString,
									Description: `Issuer Name`,
									Required:    false,
								},
								"certificate": {
									Type:        framework.TypeString,
									Description: `Certificate`,
									Required:    false,
								},
								"ca_chain": {
									Type:        framework.TypeStringSlice,
									Description: `CA Chain`,
									Required:    false,
								},
								"leaf_not_after_behavior": {
									Type:        framework.TypeString,
									Description: `Leaf Not After Behavior`,
									Required:    false,
								},
								"usage": {
									Type:        framework.TypeStringSlice,
									Description: `Usage`,
									Required:    false,
								},
							},
						}},
					},
				},
			},

			HelpSynopsis:    pathGetIssuerHelpSyn,
			HelpDescription: pathGetIssuerHelpDesc,
		},
		{ // Fetch an issuer by name
			Pattern: "issuer/" + framework.GenericNameRegex(issuerRefParam) + "/(json|der|pem)$",

			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: operationPrefixPKI,
				OperationSuffix: "issuer-json|issuer-der|issuer-pem",
			},

			Fields: map[string]*framework.FieldSchema{
				issuerRefParam: {
					Type:        framework.TypeString,
					Description: "The name of the EJBCA CA",
				},
			},

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathFetchIssuer,
					Responses: map[int][]framework.Response{
						http.StatusOK: {{
							Description: "OK",
							Fields: map[string]*framework.FieldSchema{
								"issuer_id": {
									Type:        framework.TypeString,
									Description: `Issuer Id`,
									Required:    true,
								},
								"issuer_name": {
									Type:        framework.TypeString,
									Description: `Issuer Name`,
									Required:    true,
								},
								"certificate": {
									Type:        framework.TypeString,
									Description: `Certificate`,
									Required:    true,
								},
								"ca_chain": {
									Type:        framework.TypeStringSlice,
									Description: `CA Chain`,
									Required:    true,
								},
							},
						}},
					},
				},
			},
		},
	}
}

func (b *ejbcaBackend) pathFetchCertList(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	sc := b.makeStorageContext(ctx, req.Storage)

	certs, err := sc.Cert().listCerts()
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(certs), nil
}

func (b *ejbcaBackend) pathFetchRevokedCertList(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	sc := b.makeStorageContext(ctx, req.Storage)

	revokedCerts, err := sc.Cert().listRevokedCerts()
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(revokedCerts), nil
}

func (b *ejbcaBackend) pathFetchCert(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	sc := b.makeStorageContext(ctx, req.Storage)

	serial := data.Get("serial").(string)
	if len(serial) == 0 {
		return logical.ErrorResponse("The serial number must be provided"), nil
	}

	if serial == "ca" || serial == "ca_chain" {
		return b.pathFetchCA(ctx, req, data)
	}

	entry, err := sc.Cert().fetchCertBundleBySerial(serial)
	if err != nil {
		switch err.(type) {
		case errutil.UserError:
			return logical.ErrorResponse(err.Error()), nil
		default:
			return nil, err
		}
	}

	// Get revocation details if applicable
	revokedEntry, err := sc.Cert().fetchRevokedCertBySerial(serial)
	if err != nil {
		switch err.(type) {
		case errutil.UserError:
			response := logical.ErrorResponse(err.Error())
			return response, nil
		default:
			return nil, err
		}
	}

	response := &logical.Response{
		Data: map[string]interface{}{},
	}

	var revocationTime int64
	var revocationTimeRfc3339 string
	if revokedEntry.Certificate != "" && revokedEntry.RevocationTime > 0 {
		revocationTime = revokedEntry.RevocationTime

		if !revokedEntry.RevocationTimeUTC.IsZero() {
			revocationTimeRfc3339 = revokedEntry.RevocationTimeUTC.Format(time.RFC3339Nano)
		}
	}

	bundle, err := entry.ToCertBundle()
	if err != nil {
		return nil, err
	}

	response.Data["certificate"] = bundle.Certificate
	response.Data["revocation_time"] = revocationTime
	response.Data["revocation_time_rfc3339"] = revocationTimeRfc3339
	response.Data["ca_chain"] = bundle.CAChain

	return response, nil
}

func (b *ejbcaBackend) pathFetchCertRaw(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	response := &logical.Response{Data: map[string]interface{}{}}
	response.Data[logical.HTTPRawBody] = []byte{}
	response.Data[logical.HTTPStatusCode] = http.StatusNoContent

	sc := b.makeStorageContext(ctx, req.Storage)

	serial := data.Get("serial").(string)
	if serial == "" {
		return response, nil
	}

	if serial == "ca" || serial == "ca_chain" {
		return b.pathFetchCA(ctx, req, data)
	}

	entry, err := sc.Cert().fetchCertBundleBySerial(serial)
	if err != nil {
		return response, nil
	}

	if entry == nil {
		return logical.ErrorResponse("No certificate found for serial " + serial), nil
	}

	var contentType string // If the request is /raw, we need to set the content type
	isPem := strings.HasSuffix(req.Path, "/pem")

	var certificate []byte

	if isPem {
		certificate = pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: entry.CertificateBytes,
		})

		contentType = "application/pem-certificate-chain"
	} else {
		contentType = "application/pkix-cert"
		certificate = []byte(base64.StdEncoding.EncodeToString(entry.CertificateBytes))
	}

	certificate = []byte(strings.TrimSpace(string(certificate)))

	response.Data[logical.HTTPContentType] = contentType
	response.Data[logical.HTTPRawBody] = certificate
	response.Data[logical.HTTPStatusCode] = http.StatusOK

	return response, nil
}

func (b *ejbcaBackend) pathFetchCA(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	sc := b.makeStorageContext(ctx, req.Storage)

	builder := caResponseBuilder{}
	return builder.Config(sc, req.Path).Build()
}

func (b *ejbcaBackend) pathFetchIssuer(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	sc := b.makeStorageContext(ctx, req.Storage)

	issuerName := strings.TrimSpace(data.Get(issuerRefParam).(string))

	builder := caResponseBuilder{}
	return builder.IssuerConfig(sc, req.Path, issuerName).Build()
}

const pathFetchHelpSyn = `
Fetch a CA, CRL, CA Chain, or non-revoked certificate from EJBCA.
`

const pathFetchHelpDesc = `
This allows certificates to be fetched. If using the fetch/ prefix any non-revoked certificate can be fetched.
Using "ca" or "crl" as the value fetches the appropriate information in DER encoding. Add "/pem" to either to get PEM encoding.
Using "ca_chain" as the value fetches the certificate authority trust chain in PEM encoding.
`

const (
	pathGetIssuerHelpSyn  = `Fetch a single issuer certificate.`
	pathGetIssuerHelpDesc = `
This allows fetching information associated with the underlying issuer
certificate.

:ref can be either the literal value "default", in which case /config/issuers
will be consulted for the present default issuer, an identifier of an issuer,
or its assigned name value.

Use /issuer/:ref/der or /issuer/:ref/pem to return just the certificate in
raw DER or PEM form, without the JSON structure of /issuer/:ref.
`
)

const pathListRevokedHelpSyn = `
List all revoked serial numbers within the local cluster
`

const pathListRevokedHelpDesc = `
Returns a list of serial numbers for revoked certificates in the local cluster. 
`
