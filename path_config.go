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
	"errors"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	configStoragePath = "config"
)

var (
	defaultCaName = "ManagementCA"
)

type ejbcaConfig struct {
	Hostname                      string   `json:"hostname"`
	ClientCert                    string   `json:"client_cert"`
	ClientKey                     string   `json:"client_key"`
	TokenURL                      string   `json:"token_url"`
	ClientID                      string   `json:"client_id"`
	ClientSecret                  string   `json:"client_secret"`
	Scopes                        []string `json:"scopes"`
	Audience                      string   `json:"audience"`
	CaCert                        string   `json:"ca_cert"`
	DefaultCAName                 string   `json:"default_ca"`
	DefaultEndEntityProfileName   string   `json:"default_end_entity_profile"`
	DefaultCertificateProfileName string   `json:"default_certificate_profile"`
	DefaultEndEntityName          string   `json:"default_end_entity_name"`
}

func pathConfig(b *ejbcaBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "config",
			Fields: map[string]*framework.FieldSchema{
				"hostname": {
					Type:        framework.TypeString,
					Description: "Hostname of the EJBCA server.",
					Required:    true,
					DisplayAttrs: &framework.DisplayAttributes{
						Name:      "Hostname",
						Sensitive: false,
					},
				},
				"client_cert": {
					Type:        framework.TypeString,
					Description: "EJBCA client certificate as a X.509 v3 PEM encoded certificate.",
					Required:    true,
					DisplayAttrs: &framework.DisplayAttributes{
						Name:      "EJBCA Client Certificate",
						Sensitive: true,
					},
				},
				"client_key": {
					Type:        framework.TypeString,
					Description: "EJBCA client key as a PKCS#8 PEM encoded private key. Must be an unencrypted PKCS#8 private key, and must match the client certificate.",
					Required:    true,
					DisplayAttrs: &framework.DisplayAttributes{
						Name:      "EJBCA Client Certificate Key",
						Sensitive: true,
					},
				},
				"token_url": {
					Type:        framework.TypeString,
					Description: "The OAuth 2.0 token URL used to obtain an access token.",
					Required:    true,
					DisplayAttrs: &framework.DisplayAttributes{
						Name:        "Token URL",
						Description: "The OAuth 2.0 token URL used to obtain an access token.",
						Sensitive:   false,
					},
				},
				"client_id": {
					Type:        framework.TypeString,
					Description: "The OAuth 2.0 client ID used to obtain an access token.",
					Required:    true,
					DisplayAttrs: &framework.DisplayAttributes{
						Name:        "Client ID",
						Description: "The OAuth 2.0 client ID used to obtain an access token.",
						Sensitive:   false,
					},
				},
				"client_secret": {
					Type:        framework.TypeString,
					Description: "The OAuth 2.0 client secret used to obtain an access token.",
					Required:    true,
					DisplayAttrs: &framework.DisplayAttributes{
						Name:        "Client Secret",
						Description: "The OAuth 2.0 client secret used to obtain an access token.",
						Sensitive:   true,
					},
				},
				"scopes": {
					Type:        framework.TypeStringSlice,
					Description: "(optional) A comma-separated list of OAuth 2.0 scopes used to obtain an access token.",
					Required:    true,
					DisplayAttrs: &framework.DisplayAttributes{
						Name:        "OAuth Scopes",
						Description: "(optional) A comma-separated list of OAuth 2.0 scopes used to obtain an access token.",
						Sensitive:   false,
					},
				},
				"audience": {
					Type:        framework.TypeString,
					Description: "(optional) The OAuth 2.0 audience used to obtain an access token.",
					Required:    true,
					DisplayAttrs: &framework.DisplayAttributes{
						Name:        "OAuth Audience",
						Description: "(optional) The OAuth 2.0 audience used to obtain an access token.",
						Sensitive:   false,
					},
				},
				"ca_cert": {
					Type:        framework.TypeString,
					Description: "EJBCA API CA certificate as a X.509 v3 PEM encoded certificate.",
					Required:    true,
					DisplayAttrs: &framework.DisplayAttributes{
						Name:      "EJBCA API CA Certificate",
						Sensitive: true,
					},
				},
				"default_ca": {
					Type:        framework.TypeString,
					Description: "The name of the default CA to use for issuing certificates.",
					Required:    false,
					Default:     defaultCaName,
					DisplayAttrs: &framework.DisplayAttributes{
						Name:      "Default CA",
						Sensitive: false,
					},
				},
				"default_end_entity_profile": {
					Type:        framework.TypeString,
					Description: "The name of the default end entity profile to use for issuing certificates.",
					Required:    false,
					Default:     "",
					DisplayAttrs: &framework.DisplayAttributes{
						Name:      "Default End Entity Profile",
						Sensitive: false,
					},
				},
				"default_certificate_profile": {
					Type:        framework.TypeString,
					Description: "The name of the default certificate profile to use for issuing certificates.",
					Required:    false,
					Default:     "",
					DisplayAttrs: &framework.DisplayAttributes{
						Name:      "Default Certificate Profile",
						Sensitive: false,
					},
				},
				"default_end_endity_profile": {
					Type: framework.TypeString,
					Description: `The name of the End Entity that will be created or used in EJBCA for certificate issuance. The value can be one of the following:
   * cn: Uses the Common Name from the CSR's Distinguished Name.
   * dns: Uses the first DNS Name from the CSR's Subject Alternative Names (SANs).
   * uri: Uses the first URI from the CSR's Subject Alternative Names (SANs).
   * ip: Uses the first IP Address from the CSR's Subject Alternative Names (SANs).
   * Custom Value: Any other string will be directly used as the End Entity Name.`,
					Required: false,
					Default:  "",
					DisplayAttrs: &framework.DisplayAttributes{
						Name:      "Default End Entity Profile",
						Sensitive: false,
					},
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathConfigRead,
				},
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathConfigWrite,
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathConfigWrite,
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.pathConfigDelete,
				},
			},
			ExistenceCheck:  b.pathConfigExistenceCheck,
			HelpSynopsis:    pathConfigHelpSynopsis,
			HelpDescription: pathConfigHelpDescription,
		},
	}
}

func (b *ejbcaBackend) pathConfigExistenceCheck(ctx context.Context, req *logical.Request, _ *framework.FieldData) (bool, error) {
	out, err := req.Storage.Get(ctx, req.Path)
	if err != nil {
		return false, fmt.Errorf("existence check failed: %w", err)
	}

	return out != nil, nil
}

func (b *ejbcaBackend) pathConfigRead(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	sc := b.makeStorageContext(ctx, req.Storage)
	config, err := sc.Config().getConfig()
	if err != nil {
		return nil, err
	}

	if config == nil {
		return nil, fmt.Errorf("config not found")
	}

	data := map[string]interface{}{
		"client_cert":                 config.ClientCert,
		"token_url":                   config.TokenURL,
		"client_id":                   config.ClientID,
		"scopes":                      config.Scopes,
		"audience":                    config.Audience,
		"ca_cert":                     config.CaCert,
		"hostname":                    config.Hostname,
		"default_ca":                  config.DefaultCAName,
		"default_end_entity_profile":  config.DefaultEndEntityProfileName,
		"default_certificate_profile": config.DefaultCertificateProfileName,
	}

	if config.ClientKey != "" {
		data["client_key"] = "REDACTED"
	}
	if config.ClientSecret != "" {
		data["client_secret"] = "REDACTED"
	}

	return &logical.Response{
		Data: data,
	}, nil
}

func (b *ejbcaBackend) pathConfigWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	logger := b.Logger().Named("pathConfigWrite")

	if b.isRunningOnPerformanceStandby() {
		logger.Debug("Running on performance standby - anticipating Vault to forward request to active node - returning backend readonly error")
		// If we're running on performance standby, read requests are the only valid request.
		// Forward the request to the primary node.
		return nil, logical.ErrReadOnly
	}

	sc := b.makeStorageContext(ctx, req.Storage)
	config, err := sc.Config().getConfig()
	if err != nil {
		return nil, err
	}

	createOperation := req.Operation == logical.CreateOperation

	if config == nil {
		// If the operation is not a create operation and the config was not found in memory, return an error
		if !createOperation {
			return nil, errors.New("config not found during update operation")
		}

		logger.Trace("EJBCA Config not found in storage, creating new")
		config = new(ejbcaConfig)
	}

	if clientCert, ok := data.GetOk("client_cert"); ok {
		logger.Trace("Client certificate present")
		config.ClientCert = clientCert.(string)
	}

	if clientKey, ok := data.GetOk("client_key"); ok {
		logger.Trace("Client key present")
		config.ClientKey = clientKey.(string)
	}

	if tokenURL, ok := data.GetOk("token_url"); ok {
		logger.Trace("Token URL present")
		config.TokenURL = tokenURL.(string)
	}

	if clientID, ok := data.GetOk("client_id"); ok {
		logger.Trace("Client ID present")
		config.ClientID = clientID.(string)
	}

	if clientSecret, ok := data.GetOk("client_secret"); ok {
		logger.Trace("Client Secret present")
		config.ClientSecret = clientSecret.(string)
	}

	if scopes, ok := data.GetOk("scopes"); ok {
		logger.Trace("Scopes present")
		config.Scopes = scopes.([]string)
	}

	if audience, ok := data.GetOk("audience"); ok {
		logger.Trace("Audience present")
		config.Audience = audience.(string)
	}

	mtls := false
	authMethodValid := false
	if config.ClientCert != "" || config.ClientKey != "" {
		if config.ClientCert == "" {
			logger.Error("client_cert is required if client_key is present")
			return logical.ErrorResponse("client_cert is required if client_key is present"), nil
		}
		if config.ClientKey == "" {
			logger.Error("client_key is required if client_cert is present")
			return logical.ErrorResponse("client_key is required if client_cert is present"), nil
		}
		mtls = true
		authMethodValid = true
	}

	if !mtls && (config.TokenURL != "" || config.ClientID != "" || config.ClientSecret != "") {
		if config.TokenURL == "" {
			logger.Error("token_url is required since there is no mTLS config present")
			return logical.ErrorResponse("token_url is required since there is no mTLS config present"), nil
		}
		if config.ClientID == "" {
			logger.Error("client_id is required since there is no mTLS config present")
			return logical.ErrorResponse("client_id is required since there is no mTLS config present"), nil
		}
		if config.ClientSecret == "" {
			logger.Error("client_secret is required since there is no mTLS config present")
			return logical.ErrorResponse("client_secret is required since there is no mTLS config present"), nil
		}
		authMethodValid = true
	}

	if !authMethodValid {
		logger.Error("Didn't find mTLS or OAuth 2.0 configuration - at least one is required.")
		return logical.ErrorResponse("Didn't find mTLS or OAuth 2.0 configuration - at least one is required."), nil
	}

	if caCert, ok := data.GetOk("ca_cert"); ok {
		logger.Trace("CA certificate present")
		config.CaCert = caCert.(string)
	}

	if hostname, ok := data.GetOk("hostname"); ok {
		logger.Trace("Hostname present", "hostname", hostname.(string))
		config.Hostname = hostname.(string)
	} else if !ok && createOperation {
		return nil, fmt.Errorf("missing hostname in configuration")
	}

	if defaultCa, ok := data.GetOk("default_ca"); ok {
		logger.Trace("Default CA present", "default_ca", defaultCa.(string))
		config.DefaultCAName = defaultCa.(string)
		// We can safely set the global defaultCaName since only one instance of Config ever exists in the backend
		logger.Trace("Globally setting default CA name", "default_ca", defaultCa.(string))
		defaultCaName = defaultCa.(string)
	} else {
		logger.Warn("default_ca not found in request")
	}

	if defaultEndEntityProfile, ok := data.GetOk("default_end_entity_profile"); ok {
		logger.Trace("Default End Entity Profile present", "default_end_entity_profile", defaultEndEntityProfile.(string))
		config.DefaultEndEntityProfileName = defaultEndEntityProfile.(string)
	} else {
		logger.Warn("default_end_entity_profile not found in request")
	}

	if defaultCertificateProfile, ok := data.GetOk("default_certificate_profile"); ok {
		logger.Trace("Default Certificate Profile present", "default_certificate_profile", defaultCertificateProfile.(string))
		config.DefaultCertificateProfileName = defaultCertificateProfile.(string)
	} else {
		logger.Warn("default_certificate_profile not found in request")
	}

	if defaultEndEntityName, ok := data.GetOk("default_end_entity_name"); ok {
		logger.Trace("Default End Entity Name present", "default_end_entity_name", defaultEndEntityName.(string))
		config.DefaultEndEntityName = defaultEndEntityName.(string)
	} else {
		logger.Warn("default_end_entity_name not found in request")
	}

	err = sc.Config().putConfig(config)
	if err != nil {
		return nil, err
	}

	logger.Debug("Finished processing pathConfigWrite")

	b.reset()

	return nil, nil
}

func (b *ejbcaBackend) pathConfigDelete(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	sc := b.makeStorageContext(ctx, req.Storage)
	err := sc.Config().deleteConfig()

	if err == nil {
		b.reset()
	}

	return nil, err
}

const pathConfigHelpSynopsis = `Configure the EJBCA backend.`

const pathConfigHelpDescription = `
The EJBCA Secrets backend uses the EJBCA REST API to generate certificates.
It is configured with the hostname of the EJBCA server, and a client certificate keypair.
The client certificate must be authenticated to the EJBCA instance.
`
