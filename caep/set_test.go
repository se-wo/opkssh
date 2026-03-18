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
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stretchr/testify/require"
)

func TestParseAndVerify_ValidSET(t *testing.T) {
	t.Parallel()
	ss := newSETServer(t)

	events := map[string]interface{}{
		EventSessionRevoked: map[string]interface{}{},
	}
	rawJWT := ss.signSET(t, testSubject, "https://myapp.example.com", events)

	set, err := ParseAndVerify(context.Background(), rawJWT, ss.URL, "https://myapp.example.com", ss.Client())
	require.NoError(t, err)
	require.NotNil(t, set)
	require.Equal(t, ss.URL, set.Issuer)
	require.Contains(t, set.Events, EventSessionRevoked)
	require.Equal(t, ss.URL, set.SubjectID.Issuer)
	require.Equal(t, testSubject, set.SubjectID.Subject)
}

func TestParseAndVerify_NoAudienceCheck(t *testing.T) {
	t.Parallel()
	ss := newSETServer(t)

	events := map[string]interface{}{
		EventSessionRevoked: map[string]interface{}{},
	}
	// Sign with an audience but pass "" expectedAudience — should still pass.
	rawJWT := ss.signSET(t, testSubject, "https://myapp.example.com", events)

	set, err := ParseAndVerify(context.Background(), rawJWT, ss.URL, "", ss.Client())
	require.NoError(t, err)
	require.NotNil(t, set)
}

func TestParseAndVerify_EmptyExpectedIssuer(t *testing.T) {
	t.Parallel()
	ss := newSETServer(t)

	events := map[string]interface{}{EventSessionRevoked: map[string]interface{}{}}
	rawJWT := ss.signSET(t, testSubject, "", events)

	_, err := ParseAndVerify(context.Background(), rawJWT, "", "", ss.Client())
	require.Error(t, err)
	require.ErrorContains(t, err, "expectedIssuer must not be empty")
}

func TestParseAndVerify_DiscoveryReturns500(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)

	// rawJWT content doesn't matter — discovery will fail first.
	_, err := ParseAndVerify(context.Background(), "dummy.jwt.token", srv.URL, "", srv.Client())
	require.Error(t, err)
	require.ErrorContains(t, err, "failed to discover JWKS URI")
}

func TestParseAndVerify_DiscoveryMissingJWKSURI(t *testing.T) {
	t.Parallel()

	// Use var + assignment so the closure can reference srv.URL after it is set.
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			w.Header().Set("Content-Type", "application/json")
			// Return a discovery doc without jwks_uri.
			json.NewEncoder(w).Encode(map[string]string{"issuer": srv.URL}) //nolint:errcheck
		} else {
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)

	_, err := ParseAndVerify(context.Background(), "dummy.jwt.token", srv.URL, "", srv.Client())
	require.Error(t, err)
	require.ErrorContains(t, err, "jwks_uri")
}

func TestParseAndVerify_JWKSFetchFailure(t *testing.T) {
	t.Parallel()

	// Use var + assignment so the closure can reference srv.URL after it is set.
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{ //nolint:errcheck
				"issuer":   srv.URL,
				"jwks_uri": srv.URL + "/jwks",
			})
		case "/jwks":
			// Return a 500 to simulate a JWKS fetch failure.
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	t.Cleanup(srv.Close)

	_, err := ParseAndVerify(context.Background(), "dummy.jwt.token", srv.URL, "", srv.Client())
	require.Error(t, err)
	require.ErrorContains(t, err, "failed to fetch JWKS")
}

func TestParseAndVerify_SignatureMismatch(t *testing.T) {
	t.Parallel()

	// Server A: provides OIDC discovery + JWKS (trusted issuer).
	ssA := newSETServer(t)

	// Build a SET with iss=ssA.URL but signed with a completely different key.
	events := map[string]interface{}{EventSessionRevoked: map[string]interface{}{}}
	rawKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	wrongKey, err := jwk.FromRaw(rawKey)
	require.NoError(t, err)

	tok := jwt.New()
	require.NoError(t, tok.Set(jwt.IssuerKey, ssA.URL))
	require.NoError(t, tok.Set("events", events))
	require.NoError(t, tok.Set("sub_id", map[string]string{"format": "iss_sub", "sub": testSubject}))
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256, wrongKey))
	require.NoError(t, err)

	// ssA's JWKS does not contain wrongKey → signature verification must fail.
	_, err = ParseAndVerify(context.Background(), string(signed), ssA.URL, "", ssA.Client())
	require.Error(t, err)
	require.ErrorContains(t, err, "SET signature verification failed")
}

func TestParseAndVerify_WrongIssClaim(t *testing.T) {
	t.Parallel()
	ss := newSETServer(t)

	// Build a SET signed by ss but with a different iss value.
	tok := jwt.New()
	require.NoError(t, tok.Set(jwt.IssuerKey, "https://evil.example.com"))
	require.NoError(t, tok.Set("events", map[string]interface{}{EventSessionRevoked: map[string]interface{}{}}))
	require.NoError(t, tok.Set("sub_id", map[string]string{"format": "iss_sub", "sub": testSubject}))

	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256, ss.privKey))
	require.NoError(t, err)

	_, err = ParseAndVerify(context.Background(), string(signed), ss.URL, "", ss.Client())
	require.Error(t, err)
	// jwt library rejects tokens whose iss doesn't match WithIssuer option.
	require.ErrorContains(t, err, "SET signature verification failed")
}

func TestParseAndVerify_EmptyEvents(t *testing.T) {
	t.Parallel()
	ss := newSETServer(t)

	// Sign a SET with no events.
	tok := jwt.New()
	require.NoError(t, tok.Set(jwt.IssuerKey, ss.URL))
	require.NoError(t, tok.Set("events", map[string]interface{}{}))
	require.NoError(t, tok.Set("sub_id", map[string]string{"format": "iss_sub", "sub": testSubject}))
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256, ss.privKey))
	require.NoError(t, err)

	_, err = ParseAndVerify(context.Background(), string(signed), ss.URL, "", ss.Client())
	require.Error(t, err)
	require.ErrorContains(t, err, "SET contains no events")
}

func TestParseAndVerify_AudienceMismatch(t *testing.T) {
	t.Parallel()
	ss := newSETServer(t)

	events := map[string]interface{}{EventSessionRevoked: map[string]interface{}{}}
	rawJWT := ss.signSET(t, testSubject, "https://correct-audience.example.com", events)

	_, err := ParseAndVerify(context.Background(), rawJWT, ss.URL, "https://wrong-audience.example.com", ss.Client())
	require.Error(t, err)
	require.ErrorContains(t, err, "SET signature verification failed")
}
