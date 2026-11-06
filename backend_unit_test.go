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
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGetClientReturnsCachedClient covers getClient's fast path: when a client
// is already cached on the backend it is returned without rebuilding. This is
// the behavior both the pre- and post-write-lock nil checks rely on.
func TestGetClientReturnsCachedClient(t *testing.T) {
	sc := newTestStorageContext(t)

	cached := &ejbcaClient{}
	sc.Backend.client = cached

	got, err := sc.getClient()
	require.NoError(t, err)
	assert.Same(t, cached, got)
}

// TestGetClientConcurrentCachedAccess exercises getClient concurrently against a
// cached client. Combined with `go test -race`, it guards against data races on
// the backend's client field. It does not assert client construction, which
// requires a configured EJBCA connection.
func TestGetClientConcurrentCachedAccess(t *testing.T) {
	sc := newTestStorageContext(t)
	sc.Backend.client = &ejbcaClient{}

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := sc.getClient(); err != nil {
				t.Errorf("unexpected error from getClient: %v", err)
			}
		}()
	}
	wg.Wait()
}
