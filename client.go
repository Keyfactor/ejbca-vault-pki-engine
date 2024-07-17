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
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/Keyfactor/ejbca-go-client-sdk/api/ejbca"
	"github.com/hashicorp/vault/sdk/logical"
)

type ejbcaClient struct {
	*ejbca.APIClient
}

type newEjbcaAuthenticatorFunc func(context.Context) (ejbca.Authenticator, error)

// ejbcaAPIError is an intermediate interface that allows the EJBCA Vault PKI Engine to return
// the EJBCA API error code as the Vault API error code.
type ejbcaAPIError struct {
	Message string
	Code    int
}

func (e ejbcaAPIError) Error() string {
	return e.Message
}

// ToLogicalResponse converts the error message and HTTP error code into a raw logical.Response object.
func (e ejbcaAPIError) ToLogicalResponse() (*logical.Response, error) {
	var err error
	if e.Code == 0 {
		e.Code = http.StatusInternalServerError
	}
	jsonBody, err := json.Marshal(map[string]interface{}{
		"errors": []string{e.Message},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal EJBCA error to json: %w", err)
	}

	response := &logical.Response{
		Data: map[string]interface{}{
			logical.HTTPContentType: "application/json",
			logical.HTTPStatusCode:  e.Code,
			logical.HTTPRawBody:     string(jsonBody),
		},
	}
	return response, err
}

func (e *ejbcaClient) EjbcaAPIError(b *ejbcaBackend, detail string, err error) error {
	logger := b.Logger().Named("ejbcaClient.createErrorFromEjbcaErr")
	if err == nil {
		return nil
	}
	errString := fmt.Sprintf("%s - %s", detail, err.Error())

	// Convert Error() in the format "<code> <message>" back to an HTTP error code
	code := statusTextToCode(err.Error())
	logger.Trace(fmt.Sprintf("Mapped status message %q to code %d", err.Error(), code))

	var genericOpenAPIError *ejbca.GenericOpenAPIError
	if errors.As(err, &genericOpenAPIError) {
		errString += fmt.Sprintf(" - EJBCA API returned error %s", genericOpenAPIError.Body())
	} else {
		logger.Warn("Couldn't map EJBCA API error to more verbose error interface - API error message may be vague")
	}

	logger.Error("EJBCA returned an error!", "error", errString)

	return ejbcaAPIError{Message: errString, Code: code}
}

func statusTextToCode(statusText string) int {
	parts := strings.SplitN(statusText, " ", 2)
	if len(parts) < 2 {
		return 0
	}

	statusCode, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0
	}

	if http.StatusText(statusCode) == "" {
		return 0
	}

	return statusCode
}

// decodePEMBytes takes a byte array containing PEM encoded data and returns a slice of PEM blocks and a private key PEM block
func decodePEMBytes(buf []byte) []*pem.Block {
	var certificates []*pem.Block
	var block *pem.Block
	for {
		block, buf = pem.Decode(buf)
		if block == nil {
			break
		}
		certificates = append(certificates, block)
	}
	return certificates
}
