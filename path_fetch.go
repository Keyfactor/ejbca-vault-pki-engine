package ejbca_vault_pki_engine

import (
	"context"
	"encoding/pem"
	"fmt"
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
			"issuer_id": {
				Type:        framework.TypeString,
				Description: `ID of the issuer`,
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
	entries, err := req.Storage.List(ctx, "certs/")
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(entries), nil
}

func (b *ejbcaBackend) pathFetchCert(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	sc := b.makeStorageContext(ctx, req.Storage)

	serial := data.Get("serial").(string)
	if len(serial) == 0 {
		return logical.ErrorResponse("The serial number must be provided"), nil
	}

	certEntry, err := sc.Cert().fetchCertBySerial(req.Path, serial)
	if err != nil {
		switch err.(type) {
		case errutil.UserError:
			return logical.ErrorResponse(err.Error()), nil
		default:
			return nil, err
		}
	}

	block := pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certEntry.Value,
	}
	certificate := strings.TrimSpace(string(pem.EncodeToMemory(&block)))

	// Get revocation details if applicable
	revokedEntry, err := sc.Cert().fetchCertBySerial("revoked/", serial)
	if err != nil {
		switch err.(type) {
		case errutil.UserError:
			response := logical.ErrorResponse(err.Error())
			return response, nil
		default:
			return nil, err
		}
	}

	var revocationTime int64
	var revocationTimeRfc3339 string
	if revokedEntry != nil {
		var revInfo revocationInfo
		err := revokedEntry.DecodeJSON(&revInfo)
		if err != nil {
			return logical.ErrorResponse(fmt.Sprintf("Error decoding revocation entry for serial %s: %s", serial, err)), nil
		}
		revocationTime = revInfo.RevocationTime

		if !revInfo.RevocationTimeUTC.IsZero() {
			revocationTimeRfc3339 = revInfo.RevocationTimeUTC.Format(time.RFC3339Nano)
		}
	}

	response := &logical.Response{
		Data: map[string]interface{}{},
	}

	response.Data["certificate"] = certificate
	response.Data["revocation_time"] = revocationTime
	response.Data["revocation_time_rfc3339"] = revocationTimeRfc3339

	return response, nil
}

func (b *ejbcaBackend) pathFetchCertRaw(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	response := &logical.Response{}
	response.Data[logical.HTTPRawBody] = []byte{}
	response.Data[logical.HTTPStatusCode] = http.StatusNoContent

	sc := b.makeStorageContext(ctx, req.Storage)

	serial := data.Get("serial").(string)
	if serial == "" {
		return response, nil
	}

	certEntry, err := sc.Cert().fetchCertBySerial(req.Path, serial)
	if err != nil {
		return response, nil
	}

	var contentType string // If the request is /raw, we need to set the content type
	isPem := strings.HasSuffix(req.Path, "/pem")

	var certificate []byte

	if isPem {
		certificate = pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: certEntry.Value,
		})

		contentType = "application/pem-certificate-chain"
	} else {
		contentType = "application/pkix-cert"
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
