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
	"crypto/x509"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const SecretCertsEjbcaType = "ejbca_certificate"

func secretCerts(b *ejbcaBackend) *framework.Secret {
	return &framework.Secret{
		Type: SecretCertsEjbcaType,
		Fields: map[string]*framework.FieldSchema{
			"certificate": {
				Type:        framework.TypeString,
				Description: "The PEM-encoded concatenated certificate and\nissuing certificate authority",
			},
			"private_key": {
				Type:        framework.TypeString,
				Description: "The PEM-encoded private key for the certificate",
			},
			"serial": {
				Type:        framework.TypeString,
				Description: "The serial number of the certificate, for handy\nreference",
			},
		},
		Revoke: b.secretCertsRevoke,
	}
}

func (b *ejbcaBackend) secretCertsRevoke(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	if b.System().Tainted() {
		return nil, nil
	}

	if req.Secret == nil {
		return nil, fmt.Errorf("secret is nil in request")
	}

	serialInt, ok := req.Secret.InternalData["serial_number"]
	if !ok {
		return nil, fmt.Errorf("could not find serial in internal secret data")
	}

	sc := b.makeStorageContext(ctx, req.Storage)
	serial := serialInt.(string)

	entry, err := sc.Cert().fetchCertBundleBySerial(serial)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		// We can't write to revoked/ or update the CRL anyway because we don't have the cert,
		// and there's no reason to expect this will work on a subsequent
		// retry.  Just give up and let the lease get deleted.
		b.Logger().Warn("certificate revoke failed because not found in storage, treating as success", "serial", serial)
		return nil, nil
	}

	cert, err := x509.ParseCertificate(entry.CertificateBytes)
	if err != nil {
		return nil, fmt.Errorf("error parsing certificate: %w", err)
	}

	return revokeCert(sc, cert.SerialNumber.String())
}

func revokeCert(sc *storageContext, serialNumber string) (*logical.Response, error) {
	logger := sc.Backend.Logger().Named("revokeCert")
	logger.Info("revoking certificate with serial number " + serialNumber)

	client, err := sc.getClient()
	if err != nil {
		return nil, err
	}

	// Get the certificate
	parsedBundle, err := sc.Cert().fetchCertBundleBySerial(serialNumber)
	if err != nil {
		return nil, err
	}

	renormSerialNumber := strings.ReplaceAll(denormalizeSerial(serialNumber), ":", "")

	logger.Debug("Calling EJBCA to revoke certificate with serial number " + renormSerialNumber)
	execute, _, err := client.V1CertificateApi.RevokeCertificate(sc.Context, parsedBundle.Certificate.Issuer.String(), renormSerialNumber).Reason("CESSATION_OF_OPERATION").Execute()
	if err != nil {
		return nil, client.createErrorFromEjbcaErr(sc.Backend, "failed to revoke certificate with serial number "+serialNumber, err)
	}

	logger.Debug("Certificate with serial number " + renormSerialNumber + " revoked successfully")

	//remove the certificate from vault.
	err = sc.Cert().deleteCert(serialNumber)
	if err != nil {
		return nil, err
	}

	bundle, err := parsedBundle.ToCertBundle()
	if err != nil {
		return nil, err
	}

	logger.Trace("Creating revoked certificate entry")
	revokedEntry := &revokedCertEntry{
		Certificate:       bundle.Certificate,
		SerialNumber:      bundle.SerialNumber,
		RevocationTime:    execute.RevocationDate.Unix(),
		RevocationTimeUTC: execute.RevocationDate.UTC(),
	}

	err = sc.Cert().putRevokedCertEntry(revokedEntry)
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
