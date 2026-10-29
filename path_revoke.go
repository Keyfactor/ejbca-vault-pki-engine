/*
Copyright © 2024 Keyfactor

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package ejbca

import (
	"context"
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
					Description: `Certificate to revoke, in PEM format. The
certificate's issuer and serial number are read from the certificate
itself. Revocation is carried out by the configured EJBCA service
account, so the set of certificates that can be revoked is bounded by
that account's permissions in EJBCA, not by this mount.`,
				},
				"revocation_reason": {
					Type: framework.TypeString,
					Description: `Optional RFC 5280 revocation reason code. One of
NOT_REVOKED, UNSPECIFIED, KEY_COMPROMISE, CA_COMPROMISE,
AFFILIATION_CHANGED, SUPERSEDED, CESSATION_OF_OPERATION, CERTIFICATE_HOLD,
REMOVE_FROM_CRL, PRIVILEGES_WITHDRAWN, AA_COMPROMISE. Defaults to
CESSATION_OF_OPERATION.`,
					Default: defaultRevocationReason,
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
					Description: `Certificate to revoke, in PEM format. The
                    certificate's issuer and serial number are read from the
                    certificate itself. Revocation is carried out by the
                    configured EJBCA service account, so the set of
                    certificates that can be revoked is bounded by that
                    account's permissions in EJBCA, not by this mount.`,
				},
				"private_key": {
					Type: framework.TypeString,
					Description: `Key to use to verify revocation permission; must
                    be in PEM format.`,
				},
				"revocation_reason": {
					Type: framework.TypeString,
					Description: `Optional RFC 5280 revocation reason code. One of
                    NOT_REVOKED, UNSPECIFIED, KEY_COMPROMISE, CA_COMPROMISE,
                    AFFILIATION_CHANGED, SUPERSEDED, CESSATION_OF_OPERATION,
                    CERTIFICATE_HOLD, REMOVE_FROM_CRL, PRIVILEGES_WITHDRAWN,
                    AA_COMPROMISE. Defaults to CESSATION_OF_OPERATION.`,
					Default: defaultRevocationReason,
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
	logger.Debug("Path Revoke called")

	if b.isRunningOnPerformanceStandby() {
		logger.Debug("Running on performance standby - anticipating Vault to forward request to active node - returning backend readonly error")
		// If we're running on performance standby, read requests are the only valid request.
		// Forward the request to the primary node.
		return nil, logical.ErrReadOnly
	}

	builder := &revokeBuilder{}
	return builder.Config(b.makeStorageContext(ctx, req.Storage), req.Path, data).RevokeCertificate()
}

const pathRevokeHelpSyn = `
Revoke a certificate by serial number or with explicit certificate.

When calling /revoke-with-key, the private key corresponding to the
certificate must be provided to authenticate the request.
`

const pathRevokeHelpDesc = `
This allows certificates to be revoked. A root token or corresponding
private key is required.

A certificate may be identified either by its serial_number (which must
have been issued and stored by this mount) or by supplying the full
certificate. When a certificate is supplied, its issuer and serial number
are taken from the certificate itself and revocation is performed by the
configured EJBCA service account. The plugin does not verify that a
supplied certificate was issued through this mount, so the certificates
that can be revoked this way are bounded by the EJBCA service account's
permissions rather than by this mount.
`
