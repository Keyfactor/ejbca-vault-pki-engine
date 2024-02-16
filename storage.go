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
	"encoding/pem"
	"fmt"
	"github.com/hashicorp/vault/sdk/helper/certutil"
	"github.com/hashicorp/vault/sdk/helper/errutil"
	"github.com/hashicorp/vault/sdk/logical"
	"time"
)

const (
	revokedPath = "revoked/"
)

type storageContext struct {
	Context context.Context
	Storage logical.Storage
	Backend *ejbcaBackend
}

func (b *ejbcaBackend) makeStorageContext(ctx context.Context, s logical.Storage) *storageContext {
    logger := b.Logger().Named("ejbcaBackend.makeStorageContext")
    logger.Debug("Creating storage context")

	return &storageContext{
		Context: ctx,
		Storage: s,
		Backend: b,
	}
}

// ====================== roleStorageContext ======================

type roleStorageContext struct {
	storageContext *storageContext
}

func (sc *storageContext) Role() *roleStorageContext {
	return &roleStorageContext{
		storageContext: sc,
	}
}

// ====================== caStorageContext ======================

type caStorageContext struct {
	storageContext *storageContext
}

func (sc *storageContext) CA() *caStorageContext {
	return &caStorageContext{
		storageContext: sc,
	}
}

// ====================== configStorageContext ======================

type configStorageContext struct {
	storageContext *storageContext
}

func (sc *storageContext) Config() *configStorageContext {
	return &configStorageContext{
		storageContext: sc,
	}
}

func (c *configStorageContext) putConfig(config *ejbcaConfig) error {
    c.storageContext.Backend.Logger().Named("configStorageContext.putConfig").Debug("Putting configuration into storage")
	entry, err := logical.StorageEntryJSON(configStoragePath, config)
	if err != nil {
		return errutil.InternalError{Err: fmt.Sprintf("error creating storage entry for configuration: %v", err)}
	}
	return c.storageContext.Storage.Put(c.storageContext.Context, entry)
}

func (c *configStorageContext) getConfig() (*ejbcaConfig, error) {
    logger := c.storageContext.Backend.Logger().Named("configStorageContext.getConfig")
    logger.Debug("Getting configuration from storage")

	entry, err := c.storageContext.Storage.Get(c.storageContext.Context, configStoragePath)
	if err != nil {
        return nil, errutil.InternalError{Err: fmt.Sprintf("error reading root configuration: %v", err)} 
	}

	if entry == nil {
        logger.Trace("No configuration found in storage")
		return nil, nil
	}

	config := new(ejbcaConfig)
	if err := entry.DecodeJSON(&config); err != nil {
		return nil, errutil.InternalError{Err: fmt.Sprintf("error decoding root configuration: %v", err)} 
	}

    if config.Hostname == "" {
        logger.Error("Hostname not found in configuration")
        return nil, errutil.InternalError{Err: "hostname not found in configuration"}
    }
    if config.ClientCert == "" {
        logger.Error("Client certificate not found in configuration")
        return nil, errutil.InternalError{Err: "client certificate not found in configuration"}
    }
    if config.ClientKey == "" {
        logger.Error("Client key not found in configuration")
        return nil, errutil.InternalError{Err: "client key not found in configuration"}
    }

    logger.Trace("Returning configuration from storage")
	return config, nil
}

func (c *configStorageContext) deleteConfig() error {
    c.storageContext.Backend.Logger().Named("deleteConfig").Debug("Deleting configuration from storage")
	return c.storageContext.Storage.Delete(c.storageContext.Context, configStoragePath)
}

// ====================== certStorageContext ======================

type certStorageContext struct {
	storageContext *storageContext
}

func (sc *storageContext) Cert() *certStorageContext {
	return &certStorageContext{
		storageContext: sc,
	}
}

type certEntry struct {
	Certificate    string                  `json:"certificate"`      // The PEM encoded certificate
	SerialNumber   string                  `json:"serial_number"`    // The serial number of the certificate
	PrivateKeyType certutil.PrivateKeyType `json:"private_key_type"` // The type of the certificate's private key
	PrivateKey     string                  `json:"private_key"`      // The PEM encoded private key
	IssuerName     string                  `json:"issuer_name"`      // The issuer name of the certificate
}

type revokedCertEntry struct {
	Certificate       string    `json:"certificate"`   // The PEM encoded certificate
	SerialNumber      string    `json:"serial_number"` // The serial number of the certificate
	RevocationTime    int64     `json:"revocation_time"`
	RevocationTimeUTC time.Time `json:"revocation_time_utc"`
}

func (c *certStorageContext) putCertEntry(certEntry *certEntry) error {
    c.storageContext.Backend.Logger().Named("putCertEntry").Debug("Putting certificate entry into storage", "serial_number", certEntry.SerialNumber)
	entry, err := logical.StorageEntryJSON("certs/"+normalizeSerial(certEntry.SerialNumber), certEntry)
	if err != nil {
        return errutil.InternalError{Err: fmt.Sprintf("error creating storage entry for certificate with sn %s: %v", certEntry.SerialNumber, err)} 
	}
	return c.storageContext.Storage.Put(c.storageContext.Context, entry)
}

func (c *certStorageContext) putRevokedCertEntry(entry *revokedCertEntry) error {
    c.storageContext.Backend.Logger().Named("putRevokedCertEntry").Debug("Putting revoked certificate entry into storage", "serial_number", entry.SerialNumber)
	storageEntry, err := logical.StorageEntryJSON("revoked/"+normalizeSerial(entry.SerialNumber), entry)
	if err != nil {
		return fmt.Errorf("error creating storage entry for revoked certificate with sn %s: %w", entry.SerialNumber, err)
	}
	return c.storageContext.Storage.Put(c.storageContext.Context, storageEntry)
}

func (c *certStorageContext) fetchCertBundleBySerial(serial string) (*certutil.ParsedCertBundle, error) {
    logger := c.storageContext.Backend.Logger().Named("certStorageContext.fetchCertBundleBySerial")

	hyphenSerial := normalizeSerial(serial)
	path := "certs/" + hyphenSerial

    logger.Trace("Fetching certificate from storage", "path", path)

	storageEntry, err := c.storageContext.Storage.Get(c.storageContext.Context, path)
	if err != nil {
		return nil, errutil.InternalError{Err: fmt.Sprintf("error fetching certificate %s: %s", path, err)}
	}

	var parsedStorageEntry certEntry

	if storageEntry != nil && storageEntry.Value != nil && len(storageEntry.Value) > 0 {
        logger.Trace("Certificate found in storage", "path", path)

		err = storageEntry.DecodeJSON(&parsedStorageEntry)
		if err != nil {
			return nil, errutil.InternalError{Err: fmt.Sprintf("error decoding certificate entry with sn %s: %s", path, err)}
		}
	} 

	if parsedStorageEntry.Certificate == "" {
		return nil, errutil.InternalError{Err: "returned certificate bytes were empty"}
	}

	caCertBundle := &certutil.CertBundle{CAChain: []string{}}
	if parsedStorageEntry.IssuerName != "" {
		var caInfo *certutil.CAInfoBundle
		caInfo, err = c.storageContext.CA().fetchCaBundle(parsedStorageEntry.IssuerName)
		if err != nil {
			return nil, errutil.InternalError{Err: fmt.Sprintf("error fetching certificate bundle for certificate with sn %s: %s", path, err)}
		}
		fullChain := caInfo.GetFullChain()
		for _, cert := range fullChain {
			caCertBundle.CAChain = append(caCertBundle.CAChain, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Bytes})))
		}

        logger.Trace(fmt.Sprintf("Constructed CA chain for certificate with sn %q with %d certificates", serial, len(caCertBundle.CAChain)))
	}

	cert := &certutil.CertBundle{
		PrivateKeyType: parsedStorageEntry.PrivateKeyType,
		Certificate:    parsedStorageEntry.Certificate,
		CAChain:        caCertBundle.CAChain,
		PrivateKey:     parsedStorageEntry.PrivateKey,
		SerialNumber:   parsedStorageEntry.SerialNumber,
	}

	if len(caCertBundle.CAChain) > 0 {
		cert.IssuingCA = caCertBundle.CAChain[0]
	}

	bundle, err := cert.ToParsedCertBundle()
	if err != nil {
		return nil, errutil.InternalError{Err: fmt.Sprintf("error parsing certificate bundle for certificate with sn %s: %s", path, err)}
	}
    
    logger.Trace("Returning certificate bundle from storage", "path", path)

	return bundle, nil
}

func (c *certStorageContext) fetchRevokedCertBySerial(serial string) (*revokedCertEntry, error) {
    logger := c.storageContext.Backend.Logger().Named("certStorageContext.fetchRevokedCertBySerial")
    logger.Debug("Fetching revoked certificate from storage", "serial_number", serial)

	path := revokedPath + normalizeSerial(serial)

	storageEntry, err := c.storageContext.Storage.Get(c.storageContext.Context, path)
	if err != nil {
		return nil, errutil.InternalError{Err: fmt.Sprintf("error fetching certificate %s: %s", path, err)}
	}

	var parsedStorageEntry revokedCertEntry

	if storageEntry != nil && storageEntry.Value != nil && len(storageEntry.Value) > 0 {
        logger.Trace("Revoked certificate found in storage", "path", path)

		err = storageEntry.DecodeJSON(&parsedStorageEntry)
		if err != nil {
			return nil, errutil.InternalError{Err: fmt.Sprintf("error decoding revoked certificate entry with sn %s: %s", path, err)}
		}
	}

    logger.Trace("Returning revoked certificate from storage", "path", path)

	return &parsedStorageEntry, nil
}

func (c *certStorageContext) deleteCert(serialNumber string) error {
    c.storageContext.Backend.Logger().Named("certStorageContext.deleteCert").Debug("Deleting certificate from storage", "serial_number", serialNumber)
	return c.storageContext.Storage.Delete(c.storageContext.Context, "certs/"+normalizeSerial(serialNumber))
}

func (c *certStorageContext) listRevokedCerts() ([]string, error) {
    logger := c.storageContext.Backend.Logger().Named("certStorageContext.listRevokedCerts")
    logger.Debug("Fetching list of revoked certificates from storage", "path", revokedPath)

	list, err := c.storageContext.Storage.List(c.storageContext.Context, revokedPath)
	if err != nil {
		return nil, fmt.Errorf("failed listing revoked certs: %w", err)
	}

	// Normalize serial back to a format people are expecting.
	for i, serial := range list {
		list[i] = denormalizeSerial(serial)
	}
    
    logger.Trace(fmt.Sprintf("Returning list of %d revoked certificates from storage", len(list)))

	return list, err
}

func (c *certStorageContext) listCerts() ([]string, error) {
    logger := c.storageContext.Backend.Logger().Named("certStorageContext.listCerts")
    logger.Debug("Fetching list of certificates from storage", "path", "certs/")

	list, err := c.storageContext.Storage.List(c.storageContext.Context, "certs/")
	if err != nil {
		return nil, errutil.InternalError{Err: fmt.Sprintf("failed listing certs: %v", err)}
	}

	// Normalize serial back to a format people are expecting.
	for i, serial := range list {
		list[i] = denormalizeSerial(serial)
	}

    logger.Trace(fmt.Sprintf("Returning list of %d certificates from storage", len(list)))

	return list, err
}
