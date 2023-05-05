package ejbca_vault_pki_engine

import (
	"crypto/x509"
	"fmt"
	"github.com/hashicorp/vault/sdk/helper/errutil"
	"github.com/hashicorp/vault/sdk/logical"
	"strings"
	"time"
)

func (c *certStorageContext) fetchCertBySerial(path string, serial string) (*logical.StorageEntry, error) {
	hyphenSerial := normalizeSerial(serial)
	colonSerial := strings.ReplaceAll(strings.ToLower(serial), "-", ":")

	var legacyPath string

	if strings.HasPrefix(path, "revoked/") {
		legacyPath = "revoked/" + colonSerial
		path = "revoked/" + hyphenSerial
	} else {
		legacyPath = "certs/" + colonSerial
		path = "certs/" + hyphenSerial
	}

	certEntry, err := c.storageContext.Storage.Get(c.storageContext.Context, path)
	if err != nil {
		return nil, errutil.InternalError{Err: fmt.Sprintf("error fetching certificate %s: %s", serial, err)}
	}
	if certEntry != nil {
		if certEntry.Value == nil || len(certEntry.Value) == 0 {
			return nil, errutil.InternalError{Err: fmt.Sprintf("returned certificate bytes for serial %s were empty", serial)}
		}
		return certEntry, nil
	}

	// Retrieve the old-style path.  We disregard errors here because they
	// always manifest on Windows, and thus the initial check for a revoked
	// cert fails would return an error when the cert isn't revoked, preventing
	// the happy path from working.
	certEntry, _ = c.storageContext.Storage.Get(c.storageContext.Context, legacyPath)
	if certEntry == nil {
		return nil, nil
	}
	if certEntry.Value == nil || len(certEntry.Value) == 0 {
		return nil, errutil.InternalError{Err: fmt.Sprintf("returned certificate bytes for serial %s were empty", serial)}
	}

	// Update old-style paths to new-style paths
	certEntry.Key = path
	if err = c.storageContext.Storage.Put(c.storageContext.Context, certEntry); err != nil {
		return nil, errutil.InternalError{Err: fmt.Sprintf("error saving certificate with serial %s to new location", serial)}
	}
	_ = c.storageContext.Storage.Delete(c.storageContext.Context, legacyPath)

	return nil, nil
}

func (c *certStorageContext) deleteCert(path string) error {
	return c.storageContext.Storage.Delete(c.storageContext.Context, path)
}

func revokeCert(sc *storageContext, cert *x509.Certificate) (*logical.Response, error) {
	// Compatibility: Don't revoke CAs if they had leases. New CAs going forward aren't issued leases.
	if cert.IsCA {
		return nil, nil
	}

	// Revoke the certificate
	client, err := sc.getClient()
	if err != nil {
		return nil, err
	}

	snHex := fmt.Sprintf("%X", cert.SerialNumber)

	execute, _, err := client.V1CertificateApi.RevokeCertificate(sc.Context, cert.Issuer.String(), snHex).Reason("CESSATION_OF_OPERATION").Execute()
	if err != nil {
		return nil, client.createErrorFromEjbcaErr(sc.Backend, "revoke certificate with serial number "+snHex, err)
	}

	sc.Backend.Logger().Info("revoked certificate with serial number " + *execute.SerialNumber)

	path := "certs/" + normalizeSerial(snHex)

	//remove the certificate from vault.
	err = sc.Cert().deleteCert(path)
	if err != nil {
		return nil, err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"revocation_time":         execute.RevocationDate.Unix(),
			"revocation_time_rfc3339": execute.RevocationDate.UTC().Format(time.RFC3339Nano),
			"state":                   "revoked",
		},
	}, nil
}

func normalizeSerial(serial string) string {
	return strings.Replace(strings.ToLower(serial), ":", "-", -1)
}
