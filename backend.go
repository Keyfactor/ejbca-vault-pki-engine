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
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"math/big"
	"strings"
	"sync"

	"github.com/Keyfactor/ejbca-go-client-sdk/api/ejbca"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/consts"
	"github.com/hashicorp/vault/sdk/helper/errutil"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	operationPrefixPKI = "ejbca"
)

// Factory returns a new backend as logical.Backend.
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := backend()
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

type ejbcaBackend struct {
	*framework.Backend
	lock   sync.RWMutex
	client *ejbcaClient
}

func backend() *ejbcaBackend {
	var b = ejbcaBackend{}

	b.Backend = &framework.Backend{
		Help: strings.TrimSpace(backendHelp),
		PathsSpecial: &logical.Paths{
			Unauthenticated: []string{
				"cert/*",
				"ca/pem",
				"ca_chain",
				"ca",
				"issuer/+/pem",
				"issuer/+/der",
				"issuer/+/json",
				"issuers/", // LIST operations append a '/' to the requested path
			},

			LocalStorage: []string{
				revokedPath,
				"certs/",
			},

			SealWrapStorage: []string{
				"config",
				"role/*",
			},
		},
		Paths: framework.PathAppend(
			pathRole(&b),
			pathConfig(&b),
			pathFetch(&b),
			pathIssue(&b),
			pathSign(&b),
			pathRevoke(&b),
			pathRevokeWithKey(&b),
		),
		Secrets: []*framework.Secret{
			secretCerts(&b),
		},
		BackendType: logical.TypeLogical,
		Invalidate:  b.invalidate,
	}
	return &b
}

// reset clears any client configuration for a new
// backend to be configured
func (b *ejbcaBackend) reset() {
	b.lock.Lock()
	defer b.lock.Unlock()
	b.client = nil
}

// invalidate clears an existing client configuration in
// the backend
func (b *ejbcaBackend) invalidate(_ context.Context, key string) {
	if key == "config" {
		b.reset()
	}
}

// getClient locks the backend as it configures and creates a
// a new client for the target API
func (sc *storageContext) getClient() (*ejbcaClient, error) {
	sc.Backend.lock.RLock()
	unlockFunc := sc.Backend.lock.RUnlock
	defer func() { unlockFunc() }()

	logger := sc.Backend.Logger().Named("storageClient.getClient")
	logger.Debug("Getting EJBCA client")

	if sc.Backend.client != nil {
		logger.Trace("Returning cached client from Backend")
		return sc.Backend.client, nil
	}

	sc.Backend.lock.RUnlock()
	sc.Backend.lock.Lock()
	unlockFunc = sc.Backend.lock.Unlock

	config, err := sc.Config().getConfig()
	if err != nil {
		return nil, err
	}

	if config == nil {
		config = new(ejbcaConfig)
	}

	logger.Trace("Creating new EJBCA authenticator")
	authenticator, err := sc.Backend.newAuthenticator(sc.Context, config)
	if err != nil {
		return nil, err
	}
	if authenticator == nil {
		logger.Error("Authenticator is nil")
		return nil, fmt.Errorf("Authenticator is nil")
	}

	logger.Trace("Creating new EJBCA client")
	sdkConfig := ejbca.NewConfiguration()
	sdkConfig.Host = config.Hostname
	sdkConfig.SetAuthenticator(authenticator)

	client, err := ejbca.NewAPIClient(sdkConfig)
	if err != nil {
		return nil, err
	}
	sc.Backend.client = &ejbcaClient{client}

	return sc.Backend.client, nil
}

func (b *ejbcaBackend) newAuthenticator(ctx context.Context, config *ejbcaConfig) (ejbca.Authenticator, error) {
	var err error
	logger := b.Logger().Named("ejbcaBackend.newAuthenticator")

	var caChain []*x509.Certificate
	if config.CaCert != "" {
		logger.Info("CA chain present - Parsing CA chain from configuration")

		blocks := decodePEMBytes([]byte(config.CaCert))
		if len(blocks) == 0 {
			return nil, errutil.UserError{Err: "didn't find pem certificate in ca_cert"}
		}

		for _, block := range blocks {
			// Parse the PEM block into an x509 certificate
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("failed to parse CA certificate: %w", err)
			}

			caChain = append(caChain, cert)
		}

		logger.Debug("Parsed CA chain", "length", len(caChain))
	}

	var authenticator ejbca.Authenticator
	switch {
	case config.ClientCert != "" && config.ClientKey != "":
		logger.Info("Creating mTLS authenticator")

		var tlsCert tls.Certificate
		tlsCert, err := tls.X509KeyPair([]byte(config.ClientCert), []byte(config.ClientKey))
		if err != nil {
			return nil, fmt.Errorf("failed to load client certificate: %w", err)
		}

		authenticator, err = ejbca.NewMTLSAuthenticatorBuilder().
			WithCaCertificates(caChain).
			WithClientCertificate(&tlsCert).
			Build()
		if err != nil {
			logger.Error("Failed to build mTLS authenticator")
			return nil, fmt.Errorf("failed to build MTLS authenticator: %w", err)
		}

		logger.Info("Created mTLS authenticator")
	case config.TokenURL != "" && config.ClientID != "" && config.ClientSecret != "":
		logger.Info("Creating OAuth authenticator")

		authenticator, err = ejbca.NewOAuthAuthenticatorBuilder().
			WithCaCertificates(caChain).
			WithTokenUrl(config.TokenURL).
			WithClientId(config.ClientID).
			WithClientSecret(config.ClientSecret).
			WithAudience(config.Audience).
			WithScopes(config.Scopes).
			Build()
		if err != nil {
			logger.Error("Failed to build OAuth authenticator")
			return nil, fmt.Errorf("failed to build OAuth authenticator: %w", err)
		}

		logger.Info("Created OAuth authenticator")
	default:
		logger.Error("no authentication method configured")
		return nil, fmt.Errorf("no authentication method configured")
	}

	return authenticator, nil
}

func (b *ejbcaBackend) isRunningOnPerformanceStandby() bool {
	return b.System().ReplicationState().HasState(consts.ReplicationPerformanceStandby)
}

// backendHelp should contain help information for the backend
const backendHelp = `
The EJBCA backend dynamically generates X.509 certificates and private keys.
After mounting this backend, credentials to manage certificates must be configured
with the "config/" endpoints.
`

func generateRandomString(length int) (string, error) {
	letters := []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	b := make([]rune, length)
	for i := range b {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
		if err != nil {
			return "", err
		}
		b[i] = letters[num.Int64()]
	}
	return string(b), nil
}
