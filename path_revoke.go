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
	"context"
	"fmt"
	"net/http"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathRevoke(b *ejbcaBackend) []*framework.Path {
	return []*framework.Path{
		{ // Revoke a certificate
			Pattern: `revoke`,

			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: operationPrefixPKI,
				OperationVerb:   "revoke",
			},

			Fields: map[string]*framework.FieldSchema{
				"serial_number": {
					Type: framework.TypeString,
					Description: `Certificate serial number, in colon- or
hyphen-separated octal`,
				},
				"certificate": {
					Type: framework.TypeString,
					Description: `Certificate to revoke in PEM format; must be
signed by an issuer in this mount.`,
				},
			},

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.revokeCertificate,
					Responses: map[int][]framework.Response{
						http.StatusOK: {{
							Description: "OK",
							Fields: map[string]*framework.FieldSchema{
								"revocation_time": {
									Type:        framework.TypeDurationSecond,
									Description: `Revocation Time`,
									Required:    false,
								},
								"revocation_time_rfc3339": {
									Type:        framework.TypeTime,
									Description: `Revocation Time`,
									Required:    false,
								},
								"state": {
									Type:        framework.TypeString,
									Description: `Revocation State`,
									Required:    false,
								},
							},
						}},
					},
				},
			},

			HelpSynopsis:    pathRevokeHelpSyn,
			HelpDescription: pathRevokeHelpDesc,
		},
	}
}

func pathRevokeWithKey(b *ejbcaBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: `revoke-with-key`,

			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: operationPrefixPKI,
				OperationVerb:   "revoke",
				OperationSuffix: "with-key",
			},

			Fields: map[string]*framework.FieldSchema{
				"serial_number": {
					Type: framework.TypeString,
					Description: `Certificate serial number, in colon- or
                    hyphen-separated octal`,
				},
				"certificate": {
					Type: framework.TypeString,
					Description: `Certificate to revoke in PEM format; must be
                    signed by an issuer in this mount.`,
				},
				"private_key": {
					Type: framework.TypeString,
					Description: `Key to use to verify revocation permission; must
                    be in PEM format.`,
				},
			},

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.revokeCertificateWithPrivateKey,
					Responses: map[int][]framework.Response{
						http.StatusOK: {{
							Description: "OK",
							Fields: map[string]*framework.FieldSchema{
								"revocation_time": {
									Type:        framework.TypeInt64,
									Description: `Revocation Time`,
									Required:    false,
								},
								"revocation_time_rfc3339": {
									Type:        framework.TypeTime,
									Description: `Revocation Time`,
									Required:    false,
								},
								"state": {
									Type:        framework.TypeString,
									Description: `Revocation State`,
									Required:    false,
								},
							},
						}},
					},
				},
			},

			HelpSynopsis:    pathRevokeHelpSyn,
			HelpDescription: pathRevokeHelpDesc,
		},
	}
}

func (b *ejbcaBackend) revokeCertificate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	logger := b.Logger().Named("ejbcaBackend.revokeCertificate")
	sc := b.makeStorageContext(ctx, req.Storage)

	serial, serialPresent := data.GetOk("serial_number")
	certificate, certPresent := data.GetOk("certificate")
	if !serialPresent && !certPresent {
		return logical.ErrorResponse("The serial number or certificate to revoke must be provided."), nil
	} else if serialPresent && certPresent {
		return logical.ErrorResponse("Must provide either the certificate or the serial to revoke; not both."), nil
	}

	if certPresent {
		logger.Trace("Certificate present with request, serializing as PEM")
		cert, err := serializePemCert(certificate.(string))
		if err != nil {
			return nil, err
		}

		serial = cert.SerialNumber.String()
	}

	logger.Debug("Revoking certificate", "serial", serial, "certPresent", certPresent)
	return revokeCert(sc, serial.(string))
}

func (b *ejbcaBackend) revokeCertificateWithPrivateKey(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	logger := b.Logger().Named("ejbcaBackend.revokeCertificateWithPrivateKey")
	sc := b.makeStorageContext(ctx, req.Storage)

	serial, serialPresent := data.GetOk("serial_number")
	certificate, certPresent := data.GetOk("certificate")
	privateKey, keyPresent := data.GetOk("private_key")

	if !serialPresent && !certPresent {
		return logical.ErrorResponse("The serial number or certificate to revoke must be provided."), nil
	} else if serialPresent && certPresent {
		return logical.ErrorResponse("Must provide either the certificate or the serial to revoke; not both."), nil
	}

	if !keyPresent {
		return logical.ErrorResponse("The private key must be provided to revoke a certificate."), nil
	}

	if certPresent {
		logger.Trace("Certificate present with request, serializing as PEM")
		cert, err := serializePemCert(certificate.(string))
		if err != nil {
			return nil, fmt.Errorf("Error serializing certificate: %s", err)
		}

		serial = cert.SerialNumber.String()
	}

	key, err := serializePemPrivateKey(privateKey.(string))
	if err != nil {
		return nil, fmt.Errorf("Error serializing private key: %s", err)
	}

	logger.Debug("Revoking certificate", "serial", serial, "certPresent", certPresent)
	return revokeCertWithPrivateKey(sc, serial.(string), key)
}

const pathRevokeHelpSyn = `
Revoke a certificate by serial number or with explicit certificate.

When calling /revoke-with-key, the private key corresponding to the
certificate must be provided to authenticate the request.
`

const pathRevokeHelpDesc = `
This allows certificates to be revoke. A root token or corresponding
private key is required.
`
