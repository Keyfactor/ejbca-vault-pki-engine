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
	"math/rand"
	"strings"
	"sync"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/consts"
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
func (b *ejbcaBackend) invalidate(ctx context.Context, key string) {
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

	logger.Trace("Creating new EJBCA client")
	sc.Backend.client, err = newClient(config)
	if err != nil {
		return nil, err
	}

	return sc.Backend.client, nil
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

func generateRandomString(length int) string {
	letters := []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	b := make([]rune, length)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}
