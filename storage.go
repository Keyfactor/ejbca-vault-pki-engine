package ejbca_vault_pki_engine

import (
	"context"
	"fmt"
	"github.com/hashicorp/vault/sdk/logical"
)

type storageContext struct {
	Context context.Context
	Storage logical.Storage
	Backend *ejbcaBackend
}

func (b *ejbcaBackend) makeStorageContext(ctx context.Context, s logical.Storage) *storageContext {
	return &storageContext{
		Context: ctx,
		Storage: s,
		Backend: b,
	}
}

type certStorageContext struct {
	storageContext *storageContext
}

func (sc *storageContext) Cert() *certStorageContext {
	return &certStorageContext{
		storageContext: sc,
	}
}

type caStorageContext struct {
	storageContext *storageContext
}

func (sc *storageContext) CA() *caStorageContext {
	return &caStorageContext{
		storageContext: sc,
	}
}

type configStorageContext struct {
	storageContext *storageContext
}

func (sc *storageContext) Config() *configStorageContext {
	return &configStorageContext{
		storageContext: sc,
	}
}

func (c *configStorageContext) putConfig(config *ejbcaConfig) error {
	entry, err := logical.StorageEntryJSON(configStoragePath, config)
	if err != nil {
		return err
	}
	return c.storageContext.Storage.Put(c.storageContext.Context, entry)
}

func (c *configStorageContext) getConfig() (*ejbcaConfig, error) {
	entry, err := c.storageContext.Storage.Get(c.storageContext.Context, configStoragePath)
	if err != nil {
		return nil, err
	}

	if entry == nil {
		return nil, nil
	}

	config := new(ejbcaConfig)
	if err := entry.DecodeJSON(&config); err != nil {
		return nil, fmt.Errorf("error reading root configuration: %w", err)
	}

	return config, nil
}

func (c *configStorageContext) deleteConfig() error {
	return c.storageContext.Storage.Delete(c.storageContext.Context, configStoragePath)
}
