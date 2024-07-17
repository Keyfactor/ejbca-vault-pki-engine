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
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/hashicorp/go-secure-stdlib/parseutil"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/certutil"
	"github.com/hashicorp/vault/sdk/helper/consts"
	"github.com/hashicorp/vault/sdk/helper/errutil"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	roleStoragePath = "roles/"
)

var roleResponseFields = map[int][]framework.Response{
	http.StatusOK: {{
		Description: "OK",
		Fields: map[string]*framework.FieldSchema{
			"ttl": {
				Type:     framework.TypeDurationSecond,
				Required: true,
				Description: `The lease duration (validity period of the
certificate) if no specific lease duration is requested.
The lease duration controls the expiration of certificates
issued by this backend. Defaults to the system default
value or the value of max_ttl, whichever is shorter.`,
			},

			"max_ttl": {
				Type:     framework.TypeDurationSecond,
				Required: true,
				Description: `The maximum allowed lease duration. If not
set, defaults to the system maximum lease TTL.`,
			},

			"allow_localhost": {
				Type:     framework.TypeBool,
				Required: true,
				Description: `Whether to allow "localhost" and "localdomain"
as a valid common name in a request, independent of allowed_domains value.`,
			},

			"allowed_domains": {
				Type:     framework.TypeCommaStringSlice,
				Required: true,
				Description: `Specifies the domains this role is allowed
to issue certificates for. This is used with the allow_bare_domains,
allow_subdomains, and allow_glob_domains to determine matches for the
common name, DNS-typed SAN entries, and Email-typed SAN entries of
certificates. See the documentation for more information. This parameter
accepts a comma-separated string or list of domains.`,
			},

			"allow_bare_domains": {
				Type:     framework.TypeBool,
				Required: true,
				Description: `If set, clients can request certificates
for the base domains themselves, e.g. "example.com" of domains listed
in allowed_domains. This is a separate option as in some cases this can
be considered a security threat. See the documentation for more
information.`,
			},

			"allow_subdomains": {
				Type:     framework.TypeBool,
				Required: true,
				Description: `If set, clients can request certificates for
subdomains of domains listed in allowed_domains, including wildcard
subdomains. See the documentation for more information.`,
			},

			"allow_glob_domains": {
				Type:     framework.TypeBool,
				Required: true,
				Description: `If set, domains specified in allowed_domains
can include shell-style glob patterns, e.g. "ftp*.example.com".
See the documentation for more information.`,
			},

			"allow_wildcard_certificates": {
				Type:     framework.TypeBool,
				Required: true,
				Description: `If set, allows certificates with wildcards in
the common name to be issued, conforming to RFC 6125's Section 6.4.3; e.g.,
"*.example.net" or "b*z.example.net". See the documentation for more
information.`,
			},

			"allow_any_name": {
				Type:     framework.TypeBool,
				Required: true,
				Description: `If set, clients can request certificates for
any domain, regardless of allowed_domains restrictions.
See the documentation for more information.`,
			},

			"enforce_hostnames": {
				Type:     framework.TypeBool,
				Required: true,
				Description: `If set, only valid host names are allowed for
CN and DNS SANs, and the host part of email addresses. Defaults to true.`,
			},

			"allow_ip_sans": {
				Type:     framework.TypeBool,
				Required: true,
				Description: `If set, IP Subject Alternative Names are allowed.
Any valid IP is accepted and No authorization checking is performed.`,
			},

			"allowed_uri_sans": {
				Type:     framework.TypeCommaStringSlice,
				Required: true,
				Description: `If set, an array of allowed URIs for URI Subject Alternative Names.
Any valid URI is accepted, these values support globbing.`,
			},

			"allowed_uri_sans_template": {
				Type:     framework.TypeBool,
				Required: true,
				Description: `If set, Allowed URI SANs can be specified using identity template policies.
				Non-templated URI SANs are also permitted.`,
			},

			"allowed_other_sans": {
				Type:        framework.TypeCommaStringSlice,
				Required:    true,
				Description: `If set, an array of allowed other names to put in SANs. These values support globbing and must be in the format <oid>;<type>:<value>. Currently only "utf8" is a valid type. All values, including globbing values, must use this syntax, with the exception being a single "*" which allows any OID and any value (but type must still be utf8).`,
			},

			"allowed_serial_numbers": {
				Type:        framework.TypeCommaStringSlice,
				Required:    true,
				Description: `If set, an array of allowed serial numbers to put in Subject. These values support globbing.`,
			},
			"allowed_user_ids": {
				Type:        framework.TypeCommaStringSlice,
				Description: `If set, an array of allowed user-ids to put in user system login name specified here: https://www.rfc-editor.org/rfc/rfc1274#section-9.3.1`,
			},
			"server_flag": {
				Type:    framework.TypeBool,
				Default: true,
				Description: `If set, certificates are flagged for server auth use.
Defaults to true. See also RFC 5280 Section 4.2.1.12.`,
			},

			"client_flag": {
				Type:     framework.TypeBool,
				Required: true,
				Description: `If set, certificates are flagged for client auth use.
Defaults to true. See also RFC 5280 Section 4.2.1.12.`,
			},

			"code_signing_flag": {
				Type:     framework.TypeBool,
				Required: true,
				Description: `If set, certificates are flagged for code signing
use. Defaults to false. See also RFC 5280 Section 4.2.1.12.`,
			},

			"email_protection_flag": {
				Type:     framework.TypeBool,
				Required: true,
				Description: `If set, certificates are flagged for email
protection use. Defaults to false. See also RFC 5280 Section 4.2.1.12.`,
			},

			"key_type": {
				Type:     framework.TypeString,
				Required: true,
				Description: `The type of key to use; defaults to RSA. "rsa"
"ec", "ed25519" and "any" are the only valid values.`,
			},

			"key_bits": {
				Type:     framework.TypeInt,
				Required: true,
				Description: `The number of bits to use. Allowed values are
0 (universal default); with rsa key_type: 2048 (default), 3072, or
4096; with ec key_type: 224, 256 (default), 384, or 521; ignored with
ed25519.`,
			},
			"signature_bits": {
				Type:     framework.TypeInt,
				Required: true,
				Description: `The number of bits to use in the signature
algorithm; accepts 256 for SHA-2-256, 384 for SHA-2-384, and 512 for
SHA-2-512. Defaults to 0 to automatically detect based on key length
(SHA-2-256 for RSA keys, and matching the curve size for NIST P-Curves).`,
			},
			"use_pss": {
				Type:     framework.TypeBool,
				Required: false,
				Description: `Whether or not to use PSS signatures when using a
RSA key-type issuer. Defaults to false.`,
			},
			"key_usage": {
				Type:     framework.TypeCommaStringSlice,
				Required: true,
				Description: `A comma-separated string or list of key usages (not extended
key usages). Valid values can be found at
https://golang.org/pkg/crypto/x509/#KeyUsage
-- simply drop the "KeyUsage" part of the name.
To remove all key usages from being set, set
this value to an empty list. See also RFC 5280
Section 4.2.1.3.`,
			},

			"ext_key_usage": {
				Type:     framework.TypeCommaStringSlice,
				Required: true,
				Description: `A comma-separated string or list of extended key usages. Valid values can be found at
https://golang.org/pkg/crypto/x509/#ExtKeyUsage
-- simply drop the "ExtKeyUsage" part of the name.
To remove all key usages from being set, set
this value to an empty list. See also RFC 5280
Section 4.2.1.12.`,
			},

			"ext_key_usage_oids": {
				Type:        framework.TypeCommaStringSlice,
				Required:    true,
				Description: `A comma-separated string or list of extended key usage oids.`,
			},

			"use_csr_common_name": {
				Type:     framework.TypeBool,
				Required: true,
				Description: `If set, when used with a signing profile,
the common name in the CSR will be used. This
does *not* include any requested Subject Alternative
Names; use use_csr_sans for that. Defaults to true.`,
			},

			"use_csr_sans": {
				Type:     framework.TypeBool,
				Required: true,
				Description: `If set, when used with a signing profile,
the SANs in the CSR will be used. This does *not*
include the Common Name (cn); use use_csr_common_name
for that. Defaults to true.`,
			},

			"ou": {
				Type: framework.TypeCommaStringSlice,
				Description: `If set, OU (OrganizationalUnit) will be set to
this value in certificates issued by this role.`,
			},

			"organization": {
				Type: framework.TypeCommaStringSlice,
				Description: `If set, O (Organization) will be set to
this value in certificates issued by this role.`,
			},

			"country": {
				Type: framework.TypeCommaStringSlice,
				Description: `If set, Country will be set to
this value in certificates issued by this role.`,
			},

			"locality": {
				Type: framework.TypeCommaStringSlice,
				Description: `If set, Locality will be set to
this value in certificates issued by this role.`,
			},

			"province": {
				Type: framework.TypeCommaStringSlice,
				Description: `If set, Province will be set to
this value in certificates issued by this role.`,
			},

			"street_address": {
				Type: framework.TypeCommaStringSlice,
				Description: `If set, Street Address will be set to
this value in certificates issued by this role.`,
			},

			"postal_code": {
				Type: framework.TypeCommaStringSlice,
				Description: `If set, Postal Code will be set to
this value in certificates issued by this role.`,
			},

			"generate_lease": {
				Type: framework.TypeBool,
				Description: `
If set, certificates issued/signed against this role will have Vault leases
attached to them. Defaults to "false". Certificates can be revoked in EJBCA by
"vault revoke <lease_id>" when certificates are associated with leases.  It can
also be done using the "pki/revoke" endpoint. However, when lease generation is
disabled, invoking "pki/revoke" would be the only way to revoke certificates. 
When large number of certificates are generated with long
lifetimes, it is recommended that lease generation be disabled, as large amount of
leases adversely affect the startup time of Vault.`,
			},

			"no_store": {
				Type: framework.TypeBool,
				Description: `
If set, certificates issued/signed against this role will not be stored in the
storage backend. This can improve performance when issuing large numbers of 
certificates. However, certificates issued in this way cannot be enumerated
or revoked, so this option is recommended only for certificates that are
non-sensitive, or extremely short-lived. This option implies a value of "false"
for "generate_lease".`,
			},

			"require_cn": {
				Type:        framework.TypeBool,
				Description: `If set to false, makes the 'common_name' field optional while generating a certificate.`,
			},

			"cn_validations": {
				Type: framework.TypeCommaStringSlice,
				Description: `List of allowed validations to run against the
Common Name field. Values can include 'email' to validate the CN is a email
address, 'hostname' to validate the CN is a valid hostname (potentially
including wildcards). When multiple validations are specified, these take
OR semantics (either email OR hostname are allowed). The special value
'disabled' allows disabling all CN name validations, allowing for arbitrary
non-Hostname, non-Email address CNs.`,
			},

			"policy_identifiers": {
				Type: framework.TypeCommaStringSlice,
				Description: `A comma-separated string or list of policy OIDs, or a JSON list of qualified policy
information, which must include an oid, and may include a notice and/or cps url, using the form 
[{"oid"="1.3.6.1.4.1.7.8","notice"="I am a user Notice"}, {"oid"="1.3.6.1.4.1.44947.1.2.4 ","cps"="https://example.com"}].`,
			},

			"basic_constraints_valid_for_non_ca": {
				Type:        framework.TypeBool,
				Description: `Mark Basic Constraints valid when issuing non-CA certificates.`,
			},
			"not_before_duration": {
				Type:        framework.TypeDurationSecond,
				Description: `The duration before now which the certificate needs to be backdated by.`,
			},
			"not_after": {
				Type: framework.TypeString,
				Description: `Set the not after field of the certificate with specified date value.
The value format should be given in UTC format YYYY-MM-ddTHH:MM:SSZ.`,
			},
			"issuer_ref": {
				Type: framework.TypeString,
				Description: `Reference to the issuer used to sign requests
serviced by this role.`,
			},
			"end_entity_profile_name": {
				Type:        framework.TypeString,
				Description: `The name of an End Entity Profile in EJBCA that certificates will be issued against.`,
			},
			"certificate_profile_name": {
				Type:        framework.TypeString,
				Description: `The name of a Certificate Profile in EJBCA that certificates will be issued against.`,
			},
			"end_entity_name": {
				Type: framework.TypeString,
				Description: `The name of the End Entity that will be created or used in EJBCA for certificate issuance. The value can be one of the following:
   * cn: Uses the Common Name from the CSR's Distinguished Name.
   * dns: Uses the first DNS Name from the CSR's Subject Alternative Names (SANs).
   * uri: Uses the first URI from the CSR's Subject Alternative Names (SANs).
   * ip: Uses the first IP Address from the CSR's Subject Alternative Names (SANs).
   * Custom Value: Any other string will be directly used as the End Entity Name.`,
			},
			"account_binding_id": {
				Type:        framework.TypeString,
				Description: `Account binding ID to use for requests`,
			},
		},
	}},
}

type roleEntry struct {
	LeaseMax                      string        `json:"lease_max"`
	Lease                         string        `json:"lease"`
	DeprecatedMaxTTL              string        `json:"max_ttl"`
	DeprecatedTTL                 string        `json:"ttl"`
	TTL                           time.Duration `json:"ttl_duration"`
	MaxTTL                        time.Duration `json:"max_ttl_duration"`
	AllowLocalhost                bool          `json:"allow_localhost"`
	AllowedBaseDomain             string        `json:"allowed_base_domain"`
	AllowedDomainsOld             string        `json:"allowed_domains,omitempty"`
	AllowedDomains                []string      `json:"allowed_domains_list"`
	AllowBaseDomain               bool          `json:"allow_base_domain"`
	AllowBareDomains              bool          `json:"allow_bare_domains"`
	AllowSubdomains               bool          `json:"allow_subdomains"`
	AllowGlobDomains              bool          `json:"allow_glob_domains"`
	AllowWildcardCertificates     *bool         `json:"allow_wildcard_certificates,omitempty"`
	AllowAnyName                  bool          `json:"allow_any_name"`
	EnforceHostnames              bool          `json:"enforce_hostnames"`
	AllowIPSANs                   bool          `json:"allow_ip_sans"`
	ServerFlag                    bool          `json:"server_flag"`
	ClientFlag                    bool          `json:"client_flag"`
	CodeSigningFlag               bool          `json:"code_signing_flag"`
	EmailProtectionFlag           bool          `json:"email_protection_flag"`
	UseCSRCommonName              bool          `json:"use_csr_common_name"`
	UseCSRSANs                    bool          `json:"use_csr_sans"`
	KeyType                       string        `json:"key_type"`
	KeyBits                       int           `json:"key_bits"`
	UsePSS                        bool          `json:"use_pss"`
	SignatureBits                 int           `json:"signature_bits"`
	MaxPathLength                 *int          `json:",omitempty"`
	KeyUsageOld                   string        `json:"key_usage,omitempty"`
	KeyUsage                      []string      `json:"key_usage_list"`
	ExtKeyUsage                   []string      `json:"extended_key_usage_list"`
	OUOld                         string        `json:"ou,omitempty"`
	OU                            []string      `json:"ou_list"`
	OrganizationOld               string        `json:"organization,omitempty"`
	Organization                  []string      `json:"organization_list"`
	Country                       []string      `json:"country"`
	Locality                      []string      `json:"locality"`
	Province                      []string      `json:"province"`
	StreetAddress                 []string      `json:"street_address"`
	PostalCode                    []string      `json:"postal_code"`
	GenerateLease                 *bool         `json:"generate_lease,omitempty"`
	NoStore                       bool          `json:"no_store"`
	RequireCN                     bool          `json:"require_cn"`
	CNValidations                 []string      `json:"cn_validations"`
	AllowedOtherSANs              []string      `json:"allowed_other_sans"`
	AllowedSerialNumbers          []string      `json:"allowed_serial_numbers"`
	AllowedUserIDs                []string      `json:"allowed_user_ids"`
	AllowedURISANs                []string      `json:"allowed_uri_sans"`
	AllowedURISANsTemplate        bool          `json:"allowed_uri_sans_template"`
	PolicyIdentifiers             []string      `json:"policy_identifiers"`
	ExtKeyUsageOIDs               []string      `json:"ext_key_usage_oids"`
	BasicConstraintsValidForNonCA bool          `json:"basic_constraints_valid_for_non_ca"`
	NotBeforeDuration             time.Duration `json:"not_before_duration"`
	NotAfter                      string        `json:"not_after"`
	Issuer                        string        `json:"issuer"` // Issuer is the EJBCA CA name
	EndEntityProfileName          string        `json:"end_entity_profile_name"`
	CertificateProfileName        string        `json:"certificate_profile_name"`
	EndEntityName                 string        `json:"end_entity_name"`
	AccountBindingID              string        `json:"account_binding_id"`
}

func pathRole(b *ejbcaBackend) []*framework.Path {
	return []*framework.Path{
		{ // List all roles
			Pattern: roleStoragePath + "?$",

			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: operationPrefixPKI,
				OperationSuffix: "roles",
			},

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.pathRoleList,
					Responses: map[int][]framework.Response{
						http.StatusOK: {{
							Description: "OK",
							Fields: map[string]*framework.FieldSchema{
								"keys": {
									Type:        framework.TypeMap,
									Description: `List of keys`,
									Required:    false,
								},
							},
						}},
					},
				},
			},

			HelpSynopsis:    pathListRolesHelpSyn,
			HelpDescription: pathListRolesHelpDesc,
		},
		{ // Path role
			Pattern: roleStoragePath + framework.GenericNameRegex("name"),

			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: operationPrefixPKI,
				OperationSuffix: "role",
			},

			Fields: map[string]*framework.FieldSchema{
				"backend": {
					Type:        framework.TypeString,
					Description: "Backend Type",
				},

				"name": {
					Type:        framework.TypeString,
					Description: "Name of the role",
				},

				"ttl": {
					Type: framework.TypeDurationSecond,
					Description: `The lease duration (validity period of the
certificate) if no specific lease duration is requested.
The lease duration controls the expiration of certificates
issued by this backend. Defaults to the system default
value or the value of max_ttl, whichever is shorter.`,
					DisplayAttrs: &framework.DisplayAttributes{
						Name: "TTL",
					},
				},

				"max_ttl": {
					Type: framework.TypeDurationSecond,
					Description: `The maximum allowed lease duration. If not
set, defaults to the system maximum lease TTL.`,
					DisplayAttrs: &framework.DisplayAttributes{
						Name: "Max TTL",
					},
				},

				"allow_localhost": {
					Type:    framework.TypeBool,
					Default: true,
					Description: `Whether to allow "localhost" and "localdomain"
as a valid common name in a request, independent of allowed_domains value.`,
					DisplayAttrs: &framework.DisplayAttributes{
						Value: true,
					},
				},

				"allowed_domains": {
					Type: framework.TypeCommaStringSlice,
					Description: `Specifies the domains this role is allowed
to issue certificates for. This is used with the allow_bare_domains,
allow_subdomains, and allow_glob_domains to determine matches for the
common name, DNS-typed SAN entries, and Email-typed SAN entries of
certificates. See the documentation for more information. This parameter
accepts a comma-separated string or list of domains.`,
				},
				"allow_bare_domains": {
					Type: framework.TypeBool,
					Description: `If set, clients can request certificates
for the base domains themselves, e.g. "example.com" of domains listed
in allowed_domains. This is a separate option as in some cases this can
be considered a security threat. See the documentation for more
information.`,
				},

				"allow_subdomains": {
					Type: framework.TypeBool,
					Description: `If set, clients can request certificates for
subdomains of domains listed in allowed_domains, including wildcard
subdomains. See the documentation for more information.`,
				},

				"allow_glob_domains": {
					Type: framework.TypeBool,
					Description: `If set, domains specified in allowed_domains
can include shell-style glob patterns, e.g. "ftp*.example.com".
See the documentation for more information.`,
				},

				"allow_wildcard_certificates": {
					Type: framework.TypeBool,
					Description: `If set, allows certificates with wildcards in
the common name to be issued, conforming to RFC 6125's Section 6.4.3; e.g.,
"*.example.net" or "b*z.example.net". See the documentation for more
information.`,
					Default: true,
				},

				"allow_any_name": {
					Type: framework.TypeBool,
					Description: `If set, clients can request certificates for
any domain, regardless of allowed_domains restrictions.
See the documentation for more information.`,
				},

				"enforce_hostnames": {
					Type:    framework.TypeBool,
					Default: true,
					Description: `If set, only valid host names are allowed for
CN and DNS SANs, and the host part of email addresses. Defaults to true.`,
					DisplayAttrs: &framework.DisplayAttributes{
						Value: true,
					},
				},

				"allow_ip_sans": {
					Type:    framework.TypeBool,
					Default: true,
					Description: `If set, IP Subject Alternative Names are allowed.
Any valid IP is accepted and No authorization checking is performed.`,
					DisplayAttrs: &framework.DisplayAttributes{
						Name:  "Allow IP Subject Alternative Names",
						Value: true,
					},
				},

				"allowed_uri_sans": {
					Type: framework.TypeCommaStringSlice,
					Description: `If set, an array of allowed URIs for URI Subject Alternative Names.
Any valid URI is accepted, these values support globbing.`,
					DisplayAttrs: &framework.DisplayAttributes{
						Name: "Allowed URI Subject Alternative Names",
					},
				},

				"allowed_uri_sans_template": {
					Type: framework.TypeBool,
					Description: `If set, Allowed URI SANs can be specified using identity template policies.
				Non-templated URI SANs are also permitted.`,
					Default: false,
				},

				"allowed_other_sans": {
					Type:        framework.TypeCommaStringSlice,
					Description: `If set, an array of allowed other names to put in SANs. These values support globbing and must be in the format <oid>;<type>:<value>. Currently only "utf8" is a valid type. All values, including globbing values, must use this syntax, with the exception being a single "*" which allows any OID and any value (but type must still be utf8).`,
					DisplayAttrs: &framework.DisplayAttributes{
						Name: "Allowed Other Subject Alternative Names",
					},
				},

				"allowed_serial_numbers": {
					Type:        framework.TypeCommaStringSlice,
					Description: `If set, an array of allowed serial numbers to put in Subject. These values support globbing.`,
				},

				"allowed_user_ids": {
					Type:        framework.TypeCommaStringSlice,
					Description: `If set, an array of allowed user-ids to put in user system login name specified here: https://www.rfc-editor.org/rfc/rfc1274#section-9.3.1`,
				},

				"server_flag": {
					Type:    framework.TypeBool,
					Default: true,
					Description: `If set, certificates are flagged for server auth use.
Defaults to true. See also RFC 5280 Section 4.2.1.12.`,
					DisplayAttrs: &framework.DisplayAttributes{
						Value: true,
					},
				},

				"client_flag": {
					Type:    framework.TypeBool,
					Default: true,
					Description: `If set, certificates are flagged for client auth use.
Defaults to true. See also RFC 5280 Section 4.2.1.12.`,
					DisplayAttrs: &framework.DisplayAttributes{
						Value: true,
					},
				},

				"code_signing_flag": {
					Type: framework.TypeBool,
					Description: `If set, certificates are flagged for code signing
use. Defaults to false. See also RFC 5280 Section 4.2.1.12.`,
				},

				"email_protection_flag": {
					Type: framework.TypeBool,
					Description: `If set, certificates are flagged for email
protection use. Defaults to false. See also RFC 5280 Section 4.2.1.12.`,
				},

				"key_type": {
					Type:    framework.TypeString,
					Default: "rsa",
					Description: `The type of key to use; defaults to RSA. "rsa"
"ec", "ed25519" and "any" are the only valid values.`,
					AllowedValues: []interface{}{"rsa", "ec", "ed25519", "any"},
				},

				"key_bits": {
					Type:    framework.TypeInt,
					Default: 0,
					Description: `The number of bits to use. Allowed values are
0 (universal default); with rsa key_type: 2048 (default), 3072, or
4096; with ec key_type: 224, 256 (default), 384, or 521; ignored with
ed25519.`,
				},

				"signature_bits": {
					Type:    framework.TypeInt,
					Default: 0,
					Description: `The number of bits to use in the signature
algorithm; accepts 256 for SHA-2-256, 384 for SHA-2-384, and 512 for
SHA-2-512. Defaults to 0 to automatically detect based on key length
(SHA-2-256 for RSA keys, and matching the curve size for NIST P-Curves).`,
				},

				"use_pss": {
					Type:    framework.TypeBool,
					Default: false,
					Description: `Whether or not to use PSS signatures when using a
RSA key-type issuer. Defaults to false.`,
				},

				"key_usage": {
					Type:    framework.TypeCommaStringSlice,
					Default: []string{"DigitalSignature", "KeyAgreement", "KeyEncipherment"},
					Description: `A comma-separated string or list of key usages (not extended
key usages). Valid values can be found at
https://golang.org/pkg/crypto/x509/#KeyUsage
-- simply drop the "KeyUsage" part of the name.
To remove all key usages from being set, set
this value to an empty list. See also RFC 5280
Section 4.2.1.3.`,
					DisplayAttrs: &framework.DisplayAttributes{
						Value: "DigitalSignature,KeyAgreement,KeyEncipherment",
					},
				},

				"ext_key_usage": {
					Type:    framework.TypeCommaStringSlice,
					Default: []string{},
					Description: `A comma-separated string or list of extended key usages. Valid values can be found at
https://golang.org/pkg/crypto/x509/#ExtKeyUsage
-- simply drop the "ExtKeyUsage" part of the name.
To remove all key usages from being set, set
this value to an empty list. See also RFC 5280
Section 4.2.1.12.`,
					DisplayAttrs: &framework.DisplayAttributes{
						Name: "Extended Key Usage",
					},
				},

				"ext_key_usage_oids": {
					Type:        framework.TypeCommaStringSlice,
					Description: `A comma-separated string or list of extended key usage oids.`,
					DisplayAttrs: &framework.DisplayAttributes{
						Name: "Extended Key Usage OIDs",
					},
				},

				"use_csr_common_name": {
					Type:    framework.TypeBool,
					Default: true,
					Description: `If set, when used with a signing profile,
the common name in the CSR will be used. This
does *not* include any requested Subject Alternative
Names; use use_csr_sans for that. Defaults to true.`,
					DisplayAttrs: &framework.DisplayAttributes{
						Name:  "Use CSR Common Name",
						Value: true,
					},
				},

				"use_csr_sans": {
					Type:    framework.TypeBool,
					Default: true,
					Description: `If set, when used with a signing profile,
the SANs in the CSR will be used. This does *not*
include the Common Name (cn); use use_csr_common_name
for that. Defaults to true.`,
					DisplayAttrs: &framework.DisplayAttributes{
						Name:  "Use CSR Subject Alternative Names",
						Value: true,
					},
				},

				"ou": {
					Type: framework.TypeCommaStringSlice,
					Description: `If set, OU (OrganizationalUnit) will be set to
this value in certificates issued by this role.`,
					DisplayAttrs: &framework.DisplayAttributes{
						Name: "Organizational Unit",
					},
				},

				"organization": {
					Type: framework.TypeCommaStringSlice,
					Description: `If set, O (Organization) will be set to
this value in certificates issued by this role.`,
				},

				"country": {
					Type: framework.TypeCommaStringSlice,
					Description: `If set, Country will be set to
this value in certificates issued by this role.`,
				},

				"locality": {
					Type: framework.TypeCommaStringSlice,
					Description: `If set, Locality will be set to
this value in certificates issued by this role.`,
					DisplayAttrs: &framework.DisplayAttributes{
						Name: "Locality/City",
					},
				},

				"province": {
					Type: framework.TypeCommaStringSlice,
					Description: `If set, Province will be set to
this value in certificates issued by this role.`,
					DisplayAttrs: &framework.DisplayAttributes{
						Name: "Province/State",
					},
				},

				"street_address": {
					Type: framework.TypeCommaStringSlice,
					Description: `If set, Street Address will be set to
this value in certificates issued by this role.`,
				},

				"postal_code": {
					Type: framework.TypeCommaStringSlice,
					Description: `If set, Postal Code will be set to
this value in certificates issued by this role.`,
				},

				"generate_lease": {
					Type: framework.TypeBool,
					Description: `
If set, certificates issued/signed against this role will have Vault leases
attached to them. Defaults to "false". Certificates can be revoked by
"vault revoke <lease_id>" when certificates are associated with leases. It can
also be done using the "pki/revoke" endpoint. However, when lease generation is
disabled, invoking "pki/revoke" would be the only way to add the certificates
to the CRL.  When large number of certificates are generated with long
lifetimes, it is recommended that lease generation be disabled, as large amount of
leases adversely affect the startup time of Vault.`,
				},

				"no_store": {
					Type: framework.TypeBool,
					Description: `
If set, certificates issued/signed against this role will not be stored in the
storage backend. This can improve performance when issuing large numbers of 
certificates. However, certificates issued in this way cannot be enumerated
or revoked, so this option is recommended only for certificates that are
non-sensitive, or extremely short-lived. This option implies a value of "false"
for "generate_lease".`,
				},

				"require_cn": {
					Type:        framework.TypeBool,
					Default:     true,
					Description: `If set to false, makes the 'common_name' field optional while generating a certificate.`,
					DisplayAttrs: &framework.DisplayAttributes{
						Name: "Require Common Name",
					},
				},

				"cn_validations": {
					Type:    framework.TypeCommaStringSlice,
					Default: []string{"email", "hostname"},
					Description: `List of allowed validations to run against the
Common Name field. Values can include 'email' to validate the CN is a email
address, 'hostname' to validate the CN is a valid hostname (potentially
including wildcards). When multiple validations are specified, these take
OR semantics (either email OR hostname are allowed). The special value
'disabled' allows disabling all CN name validations, allowing for arbitrary
non-Hostname, non-Email address CNs.`,
					DisplayAttrs: &framework.DisplayAttributes{
						Name: "Common Name Validations",
					},
				},

				"policy_identifiers": {
					Type: framework.TypeCommaStringSlice,
					Description: `A comma-separated string or list of policy OIDs, or a JSON list of qualified policy
information, which must include an oid, and may include a notice and/or cps url, using the form 
[{"oid"="1.3.6.1.4.1.7.8","notice"="I am a user Notice"}, {"oid"="1.3.6.1.4.1.44947.1.2.4 ","cps"="https://example.com"}].`,
				},

				"basic_constraints_valid_for_non_ca": {
					Type:        framework.TypeBool,
					Description: `Mark Basic Constraints valid when issuing non-CA certificates.`,
					DisplayAttrs: &framework.DisplayAttributes{
						Name: "Basic Constraints Valid for Non-CA",
					},
				},
				"not_before_duration": {
					Type:        framework.TypeDurationSecond,
					Default:     30,
					Description: `The duration before now which the certificate needs to be backdated by.`,
					DisplayAttrs: &framework.DisplayAttributes{
						Value: 30,
					},
				},
				"not_after": {
					Type: framework.TypeString,
					Description: `Set the not after field of the certificate with specified date value.
The value format should be given in UTC format YYYY-MM-ddTHH:MM:SSZ.`,
				},
				"issuer_ref": {
					Type: framework.TypeString,
					Description: `Reference to the issuer used to sign requests
serviced by this role.`,
					Default: "",
				},
				"end_entity_profile_name": {
					Type:        framework.TypeString,
					Description: `The name of the EJBCA End Entity Profile to use when creating the certificate.`,
					Default:     "",
				},
				"certificate_profile_name": {
					Type:        framework.TypeString,
					Description: `The name of the EJBCA Certificate Profile to use when creating the certificate.`,
					Default:     "",
				},
				"end_entity_name": {
					Type: framework.TypeString,
					Description: `The name of the End Entity that will be created or used in EJBCA for certificate issuance. The value can be one of the following:
       * cn: Uses the Common Name from the CSR's Distinguished Name.
       * dns: Uses the first DNS Name from the CSR's Subject Alternative Names (SANs).
       * uri: Uses the first URI from the CSR's Subject Alternative Names (SANs).
       * ip: Uses the first IP Address from the CSR's Subject Alternative Names (SANs).
       * Custom Value: Any other string will be directly used as the End Entity Name.`,
				},
				"account_binding_id": {
					Type:        framework.TypeString,
					Description: `The name of the EJBCA Account Binding to use when creating the certificate.`,
					Default:     "",
				},
			},

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback:  b.pathRoleRead,
					Responses: roleResponseFields,
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback:  b.pathRoleCreate,
					Responses: roleResponseFields,
					// Read more about why these flags are set in backend.go.
					ForwardPerformanceStandby:   true,
					ForwardPerformanceSecondary: true,
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.pathRoleDelete,
					Responses: map[int][]framework.Response{
						http.StatusNoContent: {{
							Description: "No Content",
						}},
					},
					// Read more about why these flags are set in backend.go.
					ForwardPerformanceStandby:   true,
					ForwardPerformanceSecondary: true,
				},
			},

			HelpSynopsis:    pathRoleHelpSyn,
			HelpDescription: pathRoleHelpDesc,
		},
	}
}

// ======================= Role CRUD Operations =======================

func (b *ejbcaBackend) pathRoleList(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	b.Logger().Debug("Executing pathRoleList")

	entries, err := req.Storage.List(ctx, "role/")
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(entries), nil
}

func (b *ejbcaBackend) pathRoleRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	b.Logger().Debug("Executing pathRoleRead")

	sc := b.makeStorageContext(ctx, req.Storage)

	roleName := data.Get("name").(string)
	if roleName == "" {
		return logical.ErrorResponse("missing role name"), nil
	}

	role, err := sc.Role().getRole(roleName)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, nil
	}

	resp := &logical.Response{
		Data: role.ToResponseData(),
	}
	return resp, nil
}

func (b *ejbcaBackend) pathRoleCreate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	logger := b.Logger().Named("pathRoleCreate")

	if b.isRunningOnPerformanceStandby() {
		logger.Debug("Running on performance standby - anticipating Vault to forward request to active node - returning backend readonly error")
		// If we're running on performance standby, read requests are the only valid request.
		// Forward the request to the primary node.
		return nil, logical.ErrReadOnly
	}

	var err error
	name := data.Get("name").(string)
	logger.Debug("Executing pathRoleCreate", "name", name)

	entry := &roleEntry{
		MaxTTL:                        time.Duration(data.Get("max_ttl").(int)) * time.Second,
		TTL:                           time.Duration(data.Get("ttl").(int)) * time.Second,
		AllowLocalhost:                data.Get("allow_localhost").(bool),
		AllowedDomains:                data.Get("allowed_domains").([]string),
		AllowBareDomains:              data.Get("allow_bare_domains").(bool),
		AllowSubdomains:               data.Get("allow_subdomains").(bool),
		AllowGlobDomains:              data.Get("allow_glob_domains").(bool),
		AllowWildcardCertificates:     new(bool), // Handled specially below
		AllowAnyName:                  data.Get("allow_any_name").(bool),
		AllowedURISANsTemplate:        data.Get("allowed_uri_sans_template").(bool),
		EnforceHostnames:              data.Get("enforce_hostnames").(bool),
		AllowIPSANs:                   data.Get("allow_ip_sans").(bool),
		AllowedURISANs:                data.Get("allowed_uri_sans").([]string),
		ServerFlag:                    data.Get("server_flag").(bool),
		ClientFlag:                    data.Get("client_flag").(bool),
		CodeSigningFlag:               data.Get("code_signing_flag").(bool),
		EmailProtectionFlag:           data.Get("email_protection_flag").(bool),
		KeyType:                       data.Get("key_type").(string),
		KeyBits:                       data.Get("key_bits").(int),
		SignatureBits:                 data.Get("signature_bits").(int),
		UsePSS:                        data.Get("use_pss").(bool),
		UseCSRCommonName:              data.Get("use_csr_common_name").(bool),
		UseCSRSANs:                    data.Get("use_csr_sans").(bool),
		KeyUsage:                      data.Get("key_usage").([]string),
		ExtKeyUsage:                   data.Get("ext_key_usage").([]string),
		ExtKeyUsageOIDs:               data.Get("ext_key_usage_oids").([]string),
		OU:                            data.Get("ou").([]string),
		Organization:                  data.Get("organization").([]string),
		Country:                       data.Get("country").([]string),
		Locality:                      data.Get("locality").([]string),
		Province:                      data.Get("province").([]string),
		StreetAddress:                 data.Get("street_address").([]string),
		PostalCode:                    data.Get("postal_code").([]string),
		GenerateLease:                 new(bool),
		NoStore:                       data.Get("no_store").(bool),
		RequireCN:                     data.Get("require_cn").(bool),
		CNValidations:                 data.Get("cn_validations").([]string),
		AllowedSerialNumbers:          data.Get("allowed_serial_numbers").([]string),
		AllowedUserIDs:                data.Get("allowed_user_ids").([]string),
		PolicyIdentifiers:             getPolicyIdentifier(data, nil),
		BasicConstraintsValidForNonCA: data.Get("basic_constraints_valid_for_non_ca").(bool),
		NotBeforeDuration:             time.Duration(data.Get("not_before_duration").(int)) * time.Second,
		NotAfter:                      data.Get("not_after").(string),
		Issuer:                        data.Get("issuer_ref").(string),
		EndEntityProfileName:          data.Get("end_entity_profile_name").(string),
		CertificateProfileName:        data.Get("certificate_profile_name").(string),
		EndEntityName:                 data.Get("end_entity_name").(string),
		AccountBindingID:              data.Get("account_binding_id").(string),
	}

	allowedOtherSANs := data.Get("allowed_other_sans").([]string)
	switch {
	case len(allowedOtherSANs) == 0:
	case len(allowedOtherSANs) == 1 && allowedOtherSANs[0] == "*":
	default:
		// TODO parse and validate the SANs
	}
	entry.AllowedOtherSANs = allowedOtherSANs

	allowWildcardCertificates, present := data.GetOk("allow_wildcard_certificates")
	if !present {
		// While not the most secure default, when AllowWildcardCertificates isn't
		// explicitly specified in the request, we automatically set it to true to
		// preserve compatibility with previous versions of Vault.
		allowWildcardCertificates = true
	}
	*entry.AllowWildcardCertificates = allowWildcardCertificates.(bool)

	warning := ""
	// no_store implies generate_lease := false
	if entry.NoStore {
		*entry.GenerateLease = false
		if data.Get("generate_lease").(bool) {
			warning = "mutually exclusive values no_store=true and generate_lease=true were both specified; no_store=true takes priority"
		}
	} else {
		*entry.GenerateLease = data.Get("generate_lease").(bool)
		if *entry.GenerateLease {
			warning = "it is encouraged to disable generate_lease and rely on PKI's native capabilities when possible; this option can cause Vault-wide issues with large numbers of issued certificates"
		}
	}

	logger.Debug("Validating role entry before storing", "entry", entry)
	resp, err := entry.validate(b.makeStorageContext(ctx, req.Storage))
	if err != nil {
		var userError errutil.UserError
		if errors.As(err, &userError) {
			return logical.ErrorResponse(err.Error()), nil
		}
		var ejbcaError ejbcaAPIError
		if errors.As(err, &ejbcaError) {
			return ejbcaError.ToLogicalResponse()
		}

		return nil, err
	}
	if warning != "" {
		resp.AddWarning(warning)
	}
	if resp.IsError() {
		return resp, nil
	}

	// Store it
	jsonEntry, err := logical.StorageEntryJSON("role/"+name, entry)
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, jsonEntry); err != nil {
		return nil, err
	}

	return resp, nil
}

func (b *ejbcaBackend) pathRoleDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	b.Logger().Debug("Executing pathRoleDelete")

	err := req.Storage.Delete(ctx, "role/"+data.Get("name").(string))
	if err != nil {
		return nil, err
	}

	return nil, nil
}

func (r *roleEntry) ToResponseData() map[string]interface{} {
	responseData := map[string]interface{}{
		"ttl":                                int64(r.TTL.Seconds()),
		"max_ttl":                            int64(r.MaxTTL.Seconds()),
		"allow_localhost":                    r.AllowLocalhost,
		"allowed_domains":                    r.AllowedDomains,
		"allow_bare_domains":                 r.AllowBareDomains,
		"allow_subdomains":                   r.AllowSubdomains,
		"allow_glob_domains":                 r.AllowGlobDomains,
		"allow_wildcard_certificates":        r.AllowWildcardCertificates,
		"allow_any_name":                     r.AllowAnyName,
		"allowed_uri_sans_template":          r.AllowedURISANsTemplate,
		"enforce_hostnames":                  r.EnforceHostnames,
		"allow_ip_sans":                      r.AllowIPSANs,
		"server_flag":                        r.ServerFlag,
		"client_flag":                        r.ClientFlag,
		"code_signing_flag":                  r.CodeSigningFlag,
		"email_protection_flag":              r.EmailProtectionFlag,
		"use_csr_common_name":                r.UseCSRCommonName,
		"use_csr_sans":                       r.UseCSRSANs,
		"key_type":                           r.KeyType,
		"key_bits":                           r.KeyBits,
		"signature_bits":                     r.SignatureBits,
		"use_pss":                            r.UsePSS,
		"key_usage":                          r.KeyUsage,
		"ext_key_usage":                      r.ExtKeyUsage,
		"ext_key_usage_oids":                 r.ExtKeyUsageOIDs,
		"ou":                                 r.OU,
		"organization":                       r.Organization,
		"country":                            r.Country,
		"locality":                           r.Locality,
		"province":                           r.Province,
		"street_address":                     r.StreetAddress,
		"postal_code":                        r.PostalCode,
		"no_store":                           r.NoStore,
		"allowed_other_sans":                 r.AllowedOtherSANs,
		"allowed_serial_numbers":             r.AllowedSerialNumbers,
		"allowed_user_ids":                   r.AllowedUserIDs,
		"allowed_uri_sans":                   r.AllowedURISANs,
		"require_cn":                         r.RequireCN,
		"cn_validations":                     r.CNValidations,
		"policy_identifiers":                 r.PolicyIdentifiers,
		"basic_constraints_valid_for_non_ca": r.BasicConstraintsValidForNonCA,
		"not_before_duration":                int64(r.NotBeforeDuration.Seconds()),
		"not_after":                          r.NotAfter,
		"issuer_ref":                         r.Issuer,
		"end_entity_profile_name":            r.EndEntityProfileName,
		"certificate_profile_name":           r.CertificateProfileName,
		"account_binding_id":                 r.AccountBindingID,
	}
	if r.MaxPathLength != nil {
		responseData["max_path_length"] = r.MaxPathLength
	}
	if r.GenerateLease != nil {
		responseData["generate_lease"] = r.GenerateLease
	}
	return responseData
}

const pathListRolesHelpSyn = `List the existing roles in this backend`
const pathListRolesHelpDesc = `Roles will be listed by the role name.`
const pathRoleHelpSyn = `Manage the roles that can be created with this backend.`
const pathRoleHelpDesc = `This path lets you manage the roles that can be created with this backend.`

// ======================= Role Helper Operations =======================

func (r *roleStorageContext) getRole(name string) (*roleEntry, error) {
	entry, err := r.storageContext.Storage.Get(r.storageContext.Context, "role/"+name)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	var result roleEntry
	if err := entry.DecodeJSON(&result); err != nil {
		return nil, err
	}

	// Migrate existing saved entries and save back if changed
	modified := false
	if len(result.DeprecatedTTL) == 0 && len(result.Lease) != 0 {
		result.DeprecatedTTL = result.Lease
		result.Lease = ""
		modified = true
	}
	if result.TTL == 0 && len(result.DeprecatedTTL) != 0 {
		parsed, err := parseutil.ParseDurationSecond(result.DeprecatedTTL)
		if err != nil {
			return nil, err
		}
		result.TTL = parsed
		result.DeprecatedTTL = ""
		modified = true
	}
	if len(result.DeprecatedMaxTTL) == 0 && len(result.LeaseMax) != 0 {
		result.DeprecatedMaxTTL = result.LeaseMax
		result.LeaseMax = ""
		modified = true
	}
	if result.MaxTTL == 0 && len(result.DeprecatedMaxTTL) != 0 {
		parsed, err := parseutil.ParseDurationSecond(result.DeprecatedMaxTTL)
		if err != nil {
			return nil, err
		}
		result.MaxTTL = parsed
		result.DeprecatedMaxTTL = ""
		modified = true
	}
	if result.AllowBaseDomain {
		result.AllowBaseDomain = false
		result.AllowBareDomains = true
		modified = true
	}
	if result.AllowedDomainsOld != "" {
		result.AllowedDomains = strings.Split(result.AllowedDomainsOld, ",")
		result.AllowedDomainsOld = ""
		modified = true
	}
	if result.AllowedBaseDomain != "" {
		found := false
		for _, v := range result.AllowedDomains {
			if v == result.AllowedBaseDomain {
				found = true
				break
			}
		}
		if !found {
			result.AllowedDomains = append(result.AllowedDomains, result.AllowedBaseDomain)
		}
		result.AllowedBaseDomain = ""
		modified = true
	}
	if result.AllowWildcardCertificates == nil {
		// While not the most secure default, when AllowWildcardCertificates isn't
		// explicitly specified in the stored Role, we automatically upgrade it to
		// true to preserve compatibility with previous versions of Vault. Once this
		// field is set, this logic will not be triggered any more.
		result.AllowWildcardCertificates = new(bool)
		*result.AllowWildcardCertificates = true
		modified = true
	}

	// Upgrade generate_lease in role
	if result.GenerateLease == nil {
		// All the new roles will have GenerateLease always set to a value. A
		// nil value indicates that this role needs an upgrade. Set it to
		// `true` to not alter its current behavior.
		result.GenerateLease = new(bool)
		*result.GenerateLease = true
		modified = true
	}

	// Upgrade key usages
	if result.KeyUsageOld != "" {
		result.KeyUsage = strings.Split(result.KeyUsageOld, ",")
		result.KeyUsageOld = ""
		modified = true
	}

	// Upgrade OU
	if result.OUOld != "" {
		result.OU = strings.Split(result.OUOld, ",")
		result.OUOld = ""
		modified = true
	}

	// Upgrade Organization
	if result.OrganizationOld != "" {
		result.Organization = strings.Split(result.OrganizationOld, ",")
		result.OrganizationOld = ""
		modified = true
	}

	// Update CN Validations to be the present default, "email,hostname"
	if len(result.CNValidations) == 0 {
		result.CNValidations = []string{"email", "hostname"}
		modified = true
	}

	// Ensure the role is valid after updating.
	_, err = result.validate(r.storageContext)
	if err != nil {
		return nil, err
	}

	if modified && (r.storageContext.Backend.System().LocalMount() || !r.storageContext.Backend.System().ReplicationState().HasState(consts.ReplicationPerformanceSecondary)) {
		jsonEntry, err := logical.StorageEntryJSON("role/"+name, &result)
		if err != nil {
			return nil, err
		}
		if err := r.storageContext.Storage.Put(r.storageContext.Context, jsonEntry); err != nil {
			// Only perform upgrades on replication primary
			if !strings.Contains(err.Error(), logical.ErrReadOnly.Error()) {
				return nil, err
			}
		}
	}

	return &result, nil
}

func (r *roleEntry) validate(sc *storageContext) (*logical.Response, error) {
	logger := sc.Backend.Logger().Named("roleEntry.validate")
	logger.Debug("Validating role")

	resp := &logical.Response{}
	var err error

	if r.MaxTTL > 0 && r.TTL > r.MaxTTL {
		return logical.ErrorResponse(
			`"ttl" value must be less than "max_ttl" value`,
		), nil
	}

	if r.KeyBits, r.SignatureBits, err = certutil.ValidateDefaultOrValueKeyTypeSignatureLength(r.KeyType, r.KeyBits, r.SignatureBits); err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	if len(r.ExtKeyUsageOIDs) > 0 {
		for _, oidstr := range r.ExtKeyUsageOIDs {
			_, err := certutil.StringToOid(oidstr)
			if err != nil {
				return logical.ErrorResponse(fmt.Sprintf("%q could not be parsed as a valid oid for an extended key usage", oidstr)), nil
			}
		}
	}

	if len(r.PolicyIdentifiers) > 0 {
		_, err := certutil.CreatePolicyInformationExtensionFromStorageStrings(r.PolicyIdentifiers)
		if err != nil {
			return nil, err
		}
	}

	config, err := sc.Config().getConfig()
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	// Ensure issuers ref is set to a non-empty value. Note that we never
	// resolve the reference (to an issuerId) at role creation time; instead,
	// resolve it at use time. This allows values such as `default` or other
	// user-assigned names to "float" and change over time.
	if r.Issuer == "" {
		logger.Trace("Issuer not set, setting to default CA name", "defaultCAName", config.DefaultCAName)
		r.Issuer = config.DefaultCAName
	}
	if r.EndEntityProfileName == "" {
		logger.Trace("EndEntityProfileName not set, setting to default EndEntityProfileName", "defaultEndEntityProfileName", config.DefaultEndEntityProfileName)
		r.EndEntityProfileName = config.DefaultEndEntityProfileName
	}
	if r.CertificateProfileName == "" {
		logger.Trace("CertificateProfileName not set, setting to default CertificateProfileName", "defaultCertificateProfileName", config.DefaultCertificateProfileName)
		r.CertificateProfileName = config.DefaultCertificateProfileName
	}
	if r.EndEntityName == "" {
		logger.Trace("EndEntityName not set, setting to default EndEntityName", "defaultEndEntityName", config.DefaultEndEntityName)
		r.EndEntityName = config.DefaultEndEntityName
	}

	// We expect resolveIssuerReference to return its error as a known type to allow the
	// caller to properly handle it. IE - blindly return err if it's not nil
	err = sc.CA().resolveIssuerReference(r.Issuer)
	if err != nil {
		return nil, err
	}

	// Ensures CNValidations are alright
	r.CNValidations, err = validateCNEntries(r.CNValidations)
	if err != nil {
		return nil, errutil.UserError{Err: err.Error()}
	}

	if r.KeyType == "rsa" && r.KeyBits < 2048 {
		return nil, errutil.UserError{Err: "RSA keys < 2048 bits are unsafe and not supported"}
	}

	resp.Data = r.ToResponseData()
	return resp, nil
}

func validateCNEntries(entries []string) ([]string, error) {
	var disabledFlag, emailFlag, hostnameFlag bool
	var validatedEntries []string

	if len(entries) == 0 {
		return []string{"email", "hostname"}, nil
	}

	for _, entry := range entries {
		lowercaseEntry := strings.ToLower(entry)
		switch lowercaseEntry {
		case "disabled":
			if disabledFlag {
				return nil, fmt.Errorf("cn_validations value incorrect: `disabled` specified multiple times")
			}
			disabledFlag = true
		case "email":
			if emailFlag {
				return nil, fmt.Errorf("cn_validations value incorrect: `email` specified multiple times")
			}
			emailFlag = true
		case "hostname":
			if hostnameFlag {
				return nil, fmt.Errorf("cn_validations value incorrect: `hostname` specified multiple times")
			}
			hostnameFlag = true
		default:
			return nil, fmt.Errorf("cn_validations value incorrect: unknown type: `%s`", entry)
		}

		validatedEntries = append(validatedEntries, lowercaseEntry)
	}

	if !disabledFlag && !emailFlag && !hostnameFlag {
		return nil, fmt.Errorf("cn_validations value incorrect: must specify a value (`email` and/or `hostname`) or `disabled`")
	}

	if disabledFlag && (emailFlag || hostnameFlag) {
		return nil, fmt.Errorf("cn_validations value incorrect: cannot specify `disabled` along with `email` or `hostname`")
	}

	return validatedEntries, nil
}

func getPolicyIdentifier(data *framework.FieldData, defaultIdentifiers *[]string) []string {
	policyIdentifierEntry, ok := data.GetOk("policy_identifiers")
	if !ok {
		// No Entry for policy_identifiers
		if defaultIdentifiers != nil {
			return *defaultIdentifiers
		}
		return data.Get("policy_identifiers").([]string)
	}
	// Could Be A JSON Entry
	policyIdentifierJSONEntry := data.Raw["policy_identifiers"]
	policyIdentifierJSONString, ok := policyIdentifierJSONEntry.(string)
	if ok {
		policyIdentifiers, err := parsePolicyIdentifiersFromJSON(policyIdentifierJSONString)
		if err == nil {
			return policyIdentifiers
		}
	}
	// Else could Just Be A List of OIDs
	return policyIdentifierEntry.([]string)
}

func parsePolicyIdentifiersFromJSON(policyIdentifiers string) ([]string, error) {
	var entries []certutil.PolicyIdentifierWithQualifierEntry
	var policyIdentifierList []string
	err := json.Unmarshal([]byte(policyIdentifiers), &entries)
	if err != nil {
		return policyIdentifierList, err
	}
	policyIdentifierList = make([]string, 0, len(entries))
	for _, entry := range entries {
		policyString, err := json.Marshal(entry)
		if err != nil {
			return policyIdentifierList, err
		}
		policyIdentifierList = append(policyIdentifierList, string(policyString))
	}
	return policyIdentifierList, nil
}
