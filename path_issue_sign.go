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
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"net/http"
)

// Path                                          | Issuer         | CSR required | Subject to role restriction
// ----------------------------------------------|----------------|--------------|-----------------------------
// sign/:role_name                               | Role selected  | Yes          | Yes
// issuer/:issuer_ref/sign/:role_name            | Path selected  | Yes          | Yes
// issue/:role_name                              | Role selected  | No 		     | Yes
// issuer/:issuer_ref/issue/:role_name           | Path selected  | No           | Yes
// sign-verbatim(/:role_name)                    | default        | Yes          | No
// issuer/:issuer_ref/sign-verbatim(/:role_name) | Path selected  | Yes          | No

func addCommonIssueSignFields(fields map[string]*framework.FieldSchema) map[string]*framework.FieldSchema {
	fields["role"] = &framework.FieldSchema{
		Type: framework.TypeString,
		Description: `The desired role with configuration for this
request`,
	}

	fields["common_name"] = &framework.FieldSchema{
		Type: framework.TypeString,
		Description: `The requested common name; if you want more than
one, specify the alternative names in the
alt_names map. If email protection is enabled
in the role, this may be an email address.`,
	}

	fields["alt_names"] = &framework.FieldSchema{
		Type: framework.TypeString,
		Description: `The requested Subject Alternative Names, if any,
in a comma-delimited list. If email protection
is enabled for the role, this may contain
email addresses.`,
		DisplayAttrs: &framework.DisplayAttributes{
			Name: "DNS/Email Subject Alternative Names (SANs)",
		},
	}

	fields["serial_number"] = &framework.FieldSchema{
		Type: framework.TypeString,
		Description: `The Subject's requested serial number, if any.
See RFC 4519 Section 2.31 'serialNumber' for a description of this field.
If you want more than one, specify alternative names in the alt_names
map using OID 2.5.4.5. This has no impact on the final certificate's
Serial Number field.`,
	}

	fields["ttl"] = &framework.FieldSchema{
		Type: framework.TypeDurationSecond,
		Description: `The requested Time To Live for the certificate;
sets the expiration date. If not specified
the role default, backend default, or system
default TTL is used, in that order. Cannot
be larger than the role max TTL.`,
		DisplayAttrs: &framework.DisplayAttributes{
			Name: "TTL",
		},
	}

	fields["not_after"] = &framework.FieldSchema{
		Type: framework.TypeString,
		Description: `Set the not after field of the certificate with specified date value.
The value format should be given in UTC format YYYY-MM-ddTHH:MM:SSZ`,
	}

	fields["remove_roots_from_chain"] = &framework.FieldSchema{
		Type:    framework.TypeBool,
		Default: false,
		Description: `Whether or not to remove self-signed CA certificates in the output
of the ca_chain field.`,
	}

	fields["user_ids"] = &framework.FieldSchema{
		Type: framework.TypeCommaStringSlice,
		Description: `The requested user_ids value to place in the subject,
if any, in a comma-delimited list. Restricted by allowed_user_ids.
Any values are added with OID 0.9.2342.19200300.100.1.1.`,
		DisplayAttrs: &framework.DisplayAttributes{
			Name: "User ID(s)",
		},
	}

	fields[issuerRefParam] = &framework.FieldSchema{
		Type: framework.TypeString,
		Description: `Reference to a existing issuer; either "default"
for the configured default issuer, an identifier or the name assigned
to the issuer.`,
		Default: defaultCaName,
	}

	fields["exclude_cn_from_sans"] = &framework.FieldSchema{
		Type:    framework.TypeBool,
		Default: false,
		Description: `If true, the Common Name will not be
included in DNS or Email Subject Alternate Names.
Defaults to false (CN is included).`,
		DisplayAttrs: &framework.DisplayAttributes{
			Name: "Exclude Common Name from Subject Alternative Names (SANs)",
		},
	}

	fields["format"] = &framework.FieldSchema{
		Type:    framework.TypeString,
		Default: "pem",
		Description: `Format for returned data. Can be "pem", "der",
or "pem_bundle". If "pem_bundle", any private
key and issuing cert will be appended to the
certificate pem. If "der", the value will be
base64 encoded. Defaults to "pem".`,
		AllowedValues: []interface{}{"pem", "der", "pem_bundle"},
		DisplayAttrs: &framework.DisplayAttributes{
			Value: "pem",
		},
	}

	fields["private_key_format"] = &framework.FieldSchema{
		Type:    framework.TypeString,
		Default: "der",
		Description: `Format for the returned private key.
Generally the default will be controlled by the "format"
parameter as either base64-encoded DER or PEM-encoded DER.
However, this can be set to "pkcs8" to have the returned
private key contain base64-encoded pkcs8 or PEM-encoded
pkcs8 instead. Defaults to "der".`,
		AllowedValues: []interface{}{"", "der", "pem", "pkcs8"},
		DisplayAttrs: &framework.DisplayAttributes{
			Value: "der",
		},
	}

	fields["ip_sans"] = &framework.FieldSchema{
		Type: framework.TypeCommaStringSlice,
		Description: `The requested IP SANs, if any, in a
comma-delimited list`,
		DisplayAttrs: &framework.DisplayAttributes{
			Name: "IP Subject Alternative Names (SANs)",
		},
	}

	fields["uri_sans"] = &framework.FieldSchema{
		Type: framework.TypeCommaStringSlice,
		Description: `The requested URI SANs, if any, in a
comma-delimited list.`,
		DisplayAttrs: &framework.DisplayAttributes{
			Name: "URI Subject Alternative Names (SANs)",
		},
	}

	fields["other_sans"] = &framework.FieldSchema{
		Type: framework.TypeCommaStringSlice,
		Description: `Requested other SANs, in an array with the format
<oid>;UTF8:<utf8 string value> for each entry.`,
		DisplayAttrs: &framework.DisplayAttributes{
			Name: "Other SANs",
		},
	}

	fields["account_binding_id"] = &framework.FieldSchema{
		Type:        framework.TypeString,
		Description: `The account binding ID to use for the certificate request.`,
		DisplayAttrs: &framework.DisplayAttributes{
			Name: "EJBCA Account Binding ID",
		},
	}

	return fields
}

var pathIssueSignResponses = map[int][]framework.Response{
	http.StatusOK: {{
		Description: "OK",
		Fields: map[string]*framework.FieldSchema{
			"certificate": {
				Type:        framework.TypeString,
				Description: `Certificate`,
				Required:    true,
			},
			"issuing_ca": {
				Type:        framework.TypeString,
				Description: `Issuing Certificate Authority`,
				Required:    true,
			},
			"ca_chain": {
				Type:        framework.TypeCommaStringSlice,
				Description: `Certificate Chain`,
				Required:    false,
			},
			"serial_number": {
				Type:        framework.TypeString,
				Description: `Serial Number`,
				Required:    false,
			},
			"expiration": {
				Type:        framework.TypeString,
				Description: `Time of expiration`,
				Required:    false,
			},
			"private_key": {
				Type:        framework.TypeString,
				Description: `Private key`,
				Required:    false,
			},
			"private_key_type": {
				Type:        framework.TypeString,
				Description: `Private key type`,
				Required:    false,
			},
		},
	}},
}

func pathIssue(b *ejbcaBackend) []*framework.Path {
	return []*framework.Path{
		{ // issue/:name
			Pattern: "issue/" + framework.GenericNameRegex("role"),
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: operationPrefixPKI,
				OperationVerb:   "issue",
				OperationSuffix: "with-role",
			},

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{
					Responses: pathIssueSignResponses,
					Callback:  b.pathIssue,
				},
			},

			Fields: addCommonIssueSignFields(map[string]*framework.FieldSchema{}),

			HelpSynopsis:    pathIssueHelpSyn,
			HelpDescription: pathIssueHelpDesc,
		},
		{ // issuer/:issuer_ref/issue/:name
			Pattern: "issuer/" + framework.GenericNameRegex(issuerRefParam) + "/issue/" + framework.GenericNameRegex("role"),
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: operationPrefixPKI,
				OperationVerb:   "issue",
				OperationSuffix: "with-role",
			},

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{
					Responses: pathIssueSignResponses,
					Callback:  b.pathIssue,
				},
			},

			Fields: addCommonIssueSignFields(map[string]*framework.FieldSchema{}),

			HelpSynopsis:    pathIssueHelpSyn,
			HelpDescription: pathIssueHelpDesc,
		},
	}
}

func pathSign(b *ejbcaBackend) []*framework.Path {
	var signVerbatimFields = map[string]*framework.FieldSchema{
		"csr": {
			Type:    framework.TypeString,
			Default: "",
			Description: `PEM-format CSR to be signed. Values will be
taken verbatim from the CSR, except for
basic constraints.`,
		},
		"key_usage": {
			Type:    framework.TypeCommaStringSlice,
			Default: []string{"DigitalSignature", "KeyAgreement", "KeyEncipherment"},
			Description: `A comma-separated string or list of key usages (not extended
key usages). Valid values can be found at
https://golang.org/pkg/crypto/x509/#KeyUsage
-- simply drop the "KeyUsage" part of the name.
To remove all key usages from being set, set
this value to an empty list.`,
		},
		"ext_key_usage": {
			Type:    framework.TypeCommaStringSlice,
			Default: []string{},
			Description: `A comma-separated string or list of extended key usages. Valid values can be found at
https://golang.org/pkg/crypto/x509/#ExtKeyUsage
-- simply drop the "ExtKeyUsage" part of the name.
To remove all key usages from being set, set
this value to an empty list.`,
		},
		"ext_key_usage_oids": {
			Type:        framework.TypeCommaStringSlice,
			Description: `A comma-separated string or list of extended key usage oids.`,
		},
		"signature_bits": {
			Type:    framework.TypeInt,
			Default: 0,
			Description: `The number of bits to use in the signature
algorithm; accepts 256 for SHA-2-256, 384 for SHA-2-384, and 512 for
SHA-2-512. Defaults to 0 to automatically detect based on key length
(SHA-2-256 for RSA keys, and matching the curve size for NIST P-Curves).`,
			DisplayAttrs: &framework.DisplayAttributes{
				Value: 0,
			},
		},
		"use_pss": {
			Type:    framework.TypeBool,
			Default: false,
			Description: `Whether or not to use PSS signatures when using a
RSA key-type issuer. Defaults to false.`,
		},
	}

	return []*framework.Path{
		{ // sign/:name
			Pattern: "sign/" + framework.GenericNameRegex("role"),
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: operationPrefixPKI,
				OperationVerb:   "sign",
				OperationSuffix: "with-role",
			},

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{
					Responses: pathIssueSignResponses,
					Callback:  b.pathSign,
				},
			},

			Fields: addCommonIssueSignFields(map[string]*framework.FieldSchema{
				"csr": {
					Type:        framework.TypeString,
					Default:     "",
					Description: `PEM-format CSR to be signed.`,
				},
			}),

			HelpSynopsis:    pathSignHelpSyn,
			HelpDescription: pathSignHelpDesc,
		},
		{ // issuer/:issuer_ref/sign/:name
			Pattern: "issuer/" + framework.GenericNameRegex(issuerRefParam) + "/sign/" + framework.GenericNameRegex("role"),
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: operationPrefixPKI,
				OperationVerb:   "sign",
				OperationSuffix: "with-role",
			},

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{
					Responses: pathIssueSignResponses,
					Callback:  b.pathSign,
				},
			},

			Fields: addCommonIssueSignFields(map[string]*framework.FieldSchema{
				"csr": {
					Type:        framework.TypeString,
					Default:     "",
					Description: `PEM-format CSR to be signed.`,
				},
			}),

			HelpSynopsis:    pathSignHelpSyn,
			HelpDescription: pathSignHelpDesc,
		},
		{ // sign-verbatim(/:name)
			Pattern: "sign-verbatim" + framework.OptionalParamRegex("role"),
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: operationPrefixPKI,
				OperationVerb:   "sign",
				OperationSuffix: "verbatim|verbatim-with-role",
			},

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{
					Responses: pathIssueSignResponses,
					Callback:  b.pathSignVerbatim,
				},
			},

			Fields: addCommonIssueSignFields(signVerbatimFields),

			HelpSynopsis:    pathIssuerSignVerbatimHelpSyn,
			HelpDescription: pathIssuerSignVerbatimHelpDesc,
		},
		{ // issuer/:issuer_ref/sign-verbatim(/:name)
			Pattern: "issuer/" + framework.GenericNameRegex(issuerRefParam) + "/sign-verbatim" + framework.OptionalParamRegex("role"),
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: operationPrefixPKI,
				OperationVerb:   "sign",
				OperationSuffix: "verbatim|verbatim-with-role",
			},

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{
					Responses: pathIssueSignResponses,
					Callback:  b.pathSignVerbatim,
				},
			},

			Fields: addCommonIssueSignFields(signVerbatimFields),

			HelpSynopsis:    pathIssuerSignVerbatimHelpSyn,
			HelpDescription: pathIssuerSignVerbatimHelpDesc,
		},
	}
}

func (b *ejbcaBackend) pathIssue(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	b.Logger().Named("ejbcaBackend.pathIssue").Debug("Issue path called")
	builder := &issueSignResponseBuilder{}
	return builder.Config(b.makeStorageContext(ctx, req.Storage), req.Path, data).IssueCertificate()
}

func (b *ejbcaBackend) pathSign(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	b.Logger().Named("ejbcaBackend.pathSign").Debug("Sign path called")
	builder := &issueSignResponseBuilder{}
	return builder.Config(b.makeStorageContext(ctx, req.Storage), req.Path, data).SignCertificate()
}

func (b *ejbcaBackend) pathSignVerbatim(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	b.Logger().Named("ejbcaBackend.pathSignVerbatim").Debug("Sign Verbatim path called")
	builder := &issueSignResponseBuilder{}
	return builder.Config(b.makeStorageContext(ctx, req.Storage), req.Path, data).SignCertificate()
}

const pathIssueHelpSyn = `
Request a certificate using a certain role with the provided details.
`

const pathIssueHelpDesc = `
This path allows requesting a certificate to be issued according to the
policy of the given role. The certificate will only be issued if the
requested details are allowed by the role policy.

This path returns a certificate and a private key. If you want a workflow
that does not expose a private key, generate a CSR locally and use the
sign path instead.
`

const pathSignHelpSyn = `
Request certificates using a certain role with the provided details.
`

const pathSignHelpDesc = `
This path allows requesting certificates to be issued according to the
policy of the given role. The certificate will only be issued if the
requested common name is allowed by the role policy.

This path requires a CSR; if you want Vault to generate a private key
for you, use the issue path instead.
`

const (
	pathIssuerSignVerbatimHelpSyn  = `Issue a certificate directly based on the provided CSR.`
	pathIssuerSignVerbatimHelpDesc = `
This API endpoint allows for directly signing the specified certificate
signing request (CSR) without the typical role-based validation. This
allows for attributes from the CSR to be directly copied to the resulting
certificate.

Usually the role-based sign operations (/sign and /issue) are preferred to
this operation.

Note that this is a very privileged operation and should be extremely
restricted in terms of who is allowed to use it. All values will be taken
directly from the incoming CSR. No further verification of attribute are
performed, except as permitted by this endpoint's parameters.

See the API documentation for more information about required parameters.
`
)
