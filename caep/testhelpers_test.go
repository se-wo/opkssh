// Copyright 2025 OpenPubkey
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package caep

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stretchr/testify/require"
)

// setServer is a self-contained httptest server that exposes:
//   - /.well-known/openid-configuration — OIDC discovery document
//   - /jwks                             — JWKS endpoint for SET signature verification
//   - /poll                             — SSF polling endpoint (RFC 8936), overridable per-test
//
// It generates a fresh EC key pair on construction. Call signSET to produce
// signed SET JWTs; call setPollHandler to override the /poll handler for
// individual test scenarios.
type setServer struct {
	*httptest.Server
	privKey   jwk.Key
	jwksBytes []byte

	mu          sync.Mutex
	pollHandler http.HandlerFunc
}

// newSETServer creates and starts a new setServer. It is registered with
// t.Cleanup so the server is closed when the test ends.
func newSETServer(t *testing.T) *setServer {
	t.Helper()

	// Generate EC P-256 key pair.
	rawKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	privKey, err := jwk.FromRaw(rawKey)
	require.NoError(t, err)
	require.NoError(t, privKey.Set(jwk.KeyIDKey, "test-kid"))
	require.NoError(t, privKey.Set(jwk.AlgorithmKey, jwa.ES256))

	// Build a public JWK set for the /jwks endpoint.
	pubKey, err := privKey.PublicKey()
	require.NoError(t, err)
	require.NoError(t, pubKey.Set(jwk.KeyIDKey, "test-kid"))
	require.NoError(t, pubKey.Set(jwk.AlgorithmKey, jwa.ES256))
	set := jwk.NewSet()
	require.NoError(t, set.AddKey(pubKey))
	jwksBytes, err := json.Marshal(set)
	require.NoError(t, err)

	ss := &setServer{
		privKey:   privKey,
		jwksBytes: jwksBytes,
	}
	// Use a method-based handler so ss.URL is available inside the handler.
	ss.Server = httptest.NewServer(http.HandlerFunc(ss.handle))
	t.Cleanup(ss.Close)
	return ss
}

// handle dispatches incoming requests to the appropriate sub-handler.
func (ss *setServer) handle(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/.well-known/openid-configuration":
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{ //nolint:errcheck
			"issuer":   ss.URL,
			"jwks_uri": ss.URL + "/jwks",
		})
	case "/jwks":
		w.Header().Set("Content-Type", "application/json")
		w.Write(ss.jwksBytes) //nolint:errcheck
	case "/poll":
		ss.mu.Lock()
		h := ss.pollHandler
		ss.mu.Unlock()
		if h != nil {
			h(w, r)
		} else {
			w.WriteHeader(http.StatusNoContent)
		}
	default:
		http.NotFound(w, r)
	}
}

// setPollHandler replaces the /poll handler for the duration of the test.
// It is safe to call from multiple goroutines.
func (ss *setServer) setPollHandler(h http.HandlerFunc) {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	ss.pollHandler = h
}

// signSET creates and returns a signed SET JWT with the given subject (iss_sub
// format), audience, and events map. The SET is signed with the server's
// private key, so ParseAndVerify will accept it when given ss.URL as the
// expected issuer.
func (ss *setServer) signSET(t *testing.T, sub, audience string, events map[string]interface{}) string {
	t.Helper()

	tok := jwt.New()
	require.NoError(t, tok.Set(jwt.IssuerKey, ss.URL))
	require.NoError(t, tok.Set(jwt.JwtIDKey, "test-jti"))
	require.NoError(t, tok.Set(jwt.IssuedAtKey, time.Now()))
	if audience != "" {
		require.NoError(t, tok.Set(jwt.AudienceKey, []string{audience}))
	}
	require.NoError(t, tok.Set("events", events))
	require.NoError(t, tok.Set("sub_id", map[string]string{
		"format": "iss_sub",
		"iss":    ss.URL,
		"sub":    sub,
	}))

	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256, ss.privKey))
	require.NoError(t, err)
	return string(signed)
}

// pollResponseJSON serialises a pollResponse struct as JSON for use in /poll
// handler stubs.
func pollResponseJSON(t *testing.T, sets map[string]string, moreAvailable bool) []byte {
	t.Helper()
	resp := pollResponse{Sets: sets, MoreAvailable: moreAvailable}
	b, err := json.Marshal(resp)
	require.NoError(t, err)
	return b
}
