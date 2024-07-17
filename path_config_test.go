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
	"fmt"
	"strings"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
)

func TestConfig(t *testing.T) {
	b, reqStorage := getTestBackend(t)

	t.Run("Test Configuration mTLS", func(t *testing.T) {
		err := testConfigCreate(t, b, reqStorage, map[string]interface{}{
			"client_cert":                 clientCert,
			"client_key":                  clientKey,
			"ca_cert":                     caCert,
			"hostname":                    hostname,
			"default_ca":                  _defaultCaName,
			"default_end_entity_profile":  defaultEndEntityProfile,
			"default_certificate_profile": defaultCertificateProfile,
		})
		assert.NoError(t, err)

		err = testConfigRead(t, b, reqStorage, map[string]interface{}{
			"client_cert":                 clientCert,
			"client_key":                  clientKey,
			"token_url":                   "",
			"client_id":                   "",
			"scopes":                      []string{},
			"audience":                    "",
			"ca_cert":                     caCert,
			"hostname":                    hostname,
			"default_ca":                  _defaultCaName,
			"default_end_entity_profile":  defaultEndEntityProfile,
			"default_certificate_profile": defaultCertificateProfile,
		})
		assert.NoError(t, err)

		err = testConfigUpdate(t, b, reqStorage, map[string]interface{}{
			"client_cert":                 clientCert,
			"client_key":                  clientKey,
			"ca_cert":                     caCert,
			"hostname":                    hostname,
			"default_ca":                  _defaultCaName,
			"default_end_entity_profile":  defaultEndEntityProfile,
			"default_certificate_profile": defaultCertificateProfile,
		})
		assert.NoError(t, err)

		err = testConfigRead(t, b, reqStorage, map[string]interface{}{
			"client_cert":                 clientCert,
			"client_key":                  clientKey,
			"ca_cert":                     caCert,
			"token_url":                   "",
			"client_id":                   "",
			"scopes":                      []string{},
			"audience":                    "",
			"hostname":                    hostname,
			"default_ca":                  _defaultCaName,
			"default_end_entity_profile":  defaultEndEntityProfile,
			"default_certificate_profile": defaultCertificateProfile,
		})
		assert.NoError(t, err)

		err = testConfigDelete(t, b, reqStorage)
		assert.NoError(t, err)
	})

	t.Run("Test Configuration OAuth", func(t *testing.T) {
		const (
			tokenURL     = "1a2b3c"
			clientID     = "abc123"
			clientSecret = "123bca"
			scopes       = "read:certificates,write:certificates"
			audience     = "https://ejbca.example.com"
		)

		err := testConfigCreate(t, b, reqStorage, map[string]interface{}{
			"token_url":                   tokenURL,
			"client_id":                   clientID,
			"client_secret":               clientSecret,
			"scopes":                      strings.Split(scopes, ","),
			"audience":                    audience,
			"ca_cert":                     caCert,
			"hostname":                    hostname,
			"default_ca":                  _defaultCaName,
			"default_end_entity_profile":  defaultEndEntityProfile,
			"default_certificate_profile": defaultCertificateProfile,
		})
		assert.NoError(t, err)

		err = testConfigRead(t, b, reqStorage, map[string]interface{}{
			"client_cert":                 "",
			"token_url":                   tokenURL,
			"client_id":                   clientID,
			"client_secret":               clientSecret,
			"scopes":                      strings.Split(scopes, ","),
			"audience":                    audience,
			"ca_cert":                     caCert,
			"hostname":                    hostname,
			"default_ca":                  _defaultCaName,
			"default_end_entity_profile":  defaultEndEntityProfile,
			"default_certificate_profile": defaultCertificateProfile,
		})
		assert.NoError(t, err)

		err = testConfigUpdate(t, b, reqStorage, map[string]interface{}{
			"client_cert":                 "",
			"token_url":                   tokenURL,
			"client_id":                   clientID,
			"client_secret":               clientSecret,
			"scopes":                      strings.Split(scopes, ","),
			"audience":                    audience,
			"ca_cert":                     caCert,
			"hostname":                    hostname,
			"default_ca":                  _defaultCaName,
			"default_end_entity_profile":  defaultEndEntityProfile,
			"default_certificate_profile": defaultCertificateProfile,
		})
		assert.NoError(t, err)

		err = testConfigRead(t, b, reqStorage, map[string]interface{}{
			"client_cert":                 "",
			"token_url":                   tokenURL,
			"client_id":                   clientID,
			"client_secret":               clientSecret,
			"scopes":                      strings.Split(scopes, ","),
			"audience":                    audience,
			"ca_cert":                     caCert,
			"hostname":                    hostname,
			"default_ca":                  _defaultCaName,
			"default_end_entity_profile":  defaultEndEntityProfile,
			"default_certificate_profile": defaultCertificateProfile,
		})
		assert.NoError(t, err)

		err = testConfigDelete(t, b, reqStorage)
		assert.NoError(t, err)
	})
}

func testConfigCreate(_ *testing.T, b logical.Backend, s logical.Storage, d map[string]interface{}) error {
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      configStoragePath,
		Data:      d,
		Storage:   s,
	})

	if err != nil {
		return err
	}

	if resp != nil && resp.IsError() {
		return resp.Error()
	}
	return nil
}

func testConfigDelete(_ *testing.T, b logical.Backend, s logical.Storage) error {
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      configStoragePath,
		Storage:   s,
	})

	if err != nil {
		return err
	}

	if resp != nil && resp.IsError() {
		return resp.Error()
	}
	return nil
}

func testConfigUpdate(_ *testing.T, b logical.Backend, s logical.Storage, d map[string]interface{}) error {
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      configStoragePath,
		Data:      d,
		Storage:   s,
	})

	if err != nil {
		return err
	}

	if resp != nil && resp.IsError() {
		return resp.Error()
	}
	return nil
}

func testConfigRead(_ *testing.T, b logical.Backend, s logical.Storage, expected map[string]interface{}) error {
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      configStoragePath,
		Storage:   s,
	})

	if err != nil {
		return err
	}

	if resp == nil && expected == nil {
		return nil
	}

	if resp.IsError() {
		return resp.Error()
	}

	if len(expected) != len(resp.Data) {
		return fmt.Errorf("read data mismatch (expected %d values, got %d)", len(expected), len(resp.Data))
	}

	for k, expectedV := range expected {
		actualV, ok := resp.Data[k]

		if actualV == "REDACTED" {
			continue
		}

		if !ok {
			return fmt.Errorf(`expected data["%s"] = %v but was not included in read output`, k, expectedV)
		}

		switch expected := expectedV.(type) {
		case []string:
			if !assert.ElementsMatch(nil, expected, actualV.([]string)) {
				return fmt.Errorf(`expected data["%s"] = %v, instead got %v`, k, expected, actualV)
			}
		default:
			if expected != actualV {
				return fmt.Errorf(`expected data["%s"] = %v, instead got %v`, k, expected, actualV)
			}
		}
	}

	return nil
}
