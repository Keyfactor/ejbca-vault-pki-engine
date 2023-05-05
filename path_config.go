package ejbca_vault_pki_engine

import (
	"context"
	"errors"
	"fmt"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	configStoragePath = "config"
	defaultCaName     = "ManagementCA"
)

type ejbcaConfig struct {
	Hostname                      string `json:"hostname"`
	ClientCert                    string `json:"client_cert"`
	ClientKey                     string `json:"client_key"`
	DefaultCAName                 string `json:"default_ca"`
	DefaultEndEntityProfileName   string `json:"default_end_entity_profile"`
	DefaultCertificateProfileName string `json:"default_certificate_profile"`
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

func (b *ejbcaBackend) pathConfigExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	out, err := req.Storage.Get(ctx, req.Path)
	if err != nil {
		return false, fmt.Errorf("existence check failed: %w", err)
	}

	return out != nil, nil
}

func (b *ejbcaBackend) pathConfigRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	sc := b.makeStorageContext(ctx, req.Storage)
	config, err := sc.Config().getConfig()
	if err != nil {
		return nil, err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"client_cert":                 config.ClientCert,
			"client_key":                  config.ClientKey,
			"hostname":                    config.Hostname,
			"default_ca":                  config.DefaultCAName,
			"default_end_entity_profile":  config.DefaultEndEntityProfileName,
			"default_certificate_profile": config.DefaultCertificateProfileName,
		},
	}, nil
}

func (b *ejbcaBackend) pathConfigWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	sc := b.makeStorageContext(ctx, req.Storage)
	config, err := sc.Config().getConfig()
	if err != nil {
		return nil, err
	}

	createOperation := req.Operation == logical.CreateOperation

	if config == nil {
		if !createOperation {
			return nil, errors.New("config not found during update operation")
		}
		config = new(ejbcaConfig)
	}

	if ClientCert, ok := data.GetOk("client_cert"); ok {
		config.ClientCert = ClientCert.(string)
	} else if !ok && createOperation {
		return nil, fmt.Errorf("missing client_cert in configuration")
	}

	if ClientKey, ok := data.GetOk("client_key"); ok {
		config.ClientKey = ClientKey.(string)
	} else if !ok && createOperation {
		return nil, fmt.Errorf("missing client_key in configuration")
	}

	if hostname, ok := data.GetOk("hostname"); ok {
		config.Hostname = hostname.(string)
	} else if !ok && createOperation {
		return nil, fmt.Errorf("missing hostname in configuration")
	}

	if defaultCa, ok := data.GetOk("default_ca"); ok {
		config.DefaultCAName = defaultCa.(string)
	}

	if defaultEndEntityProfile, ok := data.GetOk("default_end_entity_profile"); ok {
		config.DefaultEndEntityProfileName = defaultEndEntityProfile.(string)
	}

	if defaultCertificateProfile, ok := data.GetOk("default_certificate_profile"); ok {
		config.DefaultCertificateProfileName = defaultCertificateProfile.(string)
	}

	err = sc.Config().putConfig(config)
	if err != nil {
		return nil, err
	}

	b.reset()

	return nil, nil
}

func (b *ejbcaBackend) pathConfigDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
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
