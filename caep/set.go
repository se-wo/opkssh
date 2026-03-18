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
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// SET is a parsed Security Event Token as defined by the Shared Signals
// Framework specification.
// https://openid.net/specs/openid-sharedsignals-framework-1_0-final.html
type SET struct {
	// Issuer is the "iss" claim — the SSF transmitter (the OIDC provider).
	Issuer string
	// JWTID is the "jti" claim — unique identifier for this SET.
	JWTID string
	// TimeOfEvent is the "toe" claim — Unix timestamp of when the event
	// occurred at the transmitter. Zero if the claim is absent.
	TimeOfEvent int64
	// Events maps each event type URI to its event-specific claims (raw JSON).
	Events map[string]json.RawMessage
	// SubjectID identifies the user this event concerns.
	SubjectID SubjectID
}

// SubjectID represents the "sub_id" claim from a SET, which identifies the
// affected subject using one of the formats defined in RFC 9493.
type SubjectID struct {
	// Format is the subject identifier format, e.g. "iss_sub", "email", "opaque".
	Format string `json:"format"`
	// Issuer and Subject are set when Format == "iss_sub".
	Issuer  string `json:"iss,omitempty"`
	Subject string `json:"sub,omitempty"`
	// Email is set when Format == "email".
	Email string `json:"email,omitempty"`
}

// rawSETClaims is used to decode the custom claims in a SET JWT that are not
// part of the standard JWT claim set.
type rawSETClaims struct {
	Events    map[string]json.RawMessage `json:"events"`
	SubjectID SubjectID                  `json:"sub_id"`
	TOE       int64                      `json:"toe"`
}

// ParseAndVerify parses a raw SET JWT string, verifies its signature using
// the issuer's public keys (fetched from OIDC discovery), validates the iss
// and aud claims, and returns the decoded SET.
//
// expectedIssuer must be non-empty. It is used directly as the OIDC discovery
// base URL rather than trusting the iss claim from the unverified token. This
// prevents SSRF attacks where a compromised polling endpoint returns SETs with
// attacker-controlled iss values, and eliminates a redundant OIDC discovery
// call since the issuer was already established during PK token verification.
//
// httpClient may be nil; http.DefaultClient is used in that case.
func ParseAndVerify(ctx context.Context, rawJWT string, expectedIssuer, expectedAudience string, httpClient *http.Client) (*SET, error) {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	if expectedIssuer == "" {
		return nil, fmt.Errorf("expectedIssuer must not be empty")
	}

	// Use the admin-configured expectedIssuer directly for JWKS discovery.
	// We do NOT pre-parse the token to extract the iss claim; trusting an
	// unverified claim from a potentially compromised endpoint would allow
	// an attacker to redirect the OIDC discovery request to an arbitrary host.
	jwksURI, err := fetchJWKSURI(ctx, expectedIssuer, httpClient)
	if err != nil {
		return nil, fmt.Errorf("failed to discover JWKS URI for issuer %q: %w", expectedIssuer, err)
	}

	keySet, err := jwk.Fetch(ctx, jwksURI, jwk.WithHTTPClient(httpClient))
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS from %q: %w", jwksURI, err)
	}

	// Verify the JWT signature and validate standard claims including iss.
	parseOpts := []jwt.ParseOption{
		jwt.WithKeySet(keySet),
		jwt.WithValidate(true),
		jwt.WithIssuer(expectedIssuer), // reject SETs not from the configured issuer
	}
	if expectedAudience != "" {
		parseOpts = append(parseOpts, jwt.WithAudience(expectedAudience))
	}

	verified, err := jwt.Parse([]byte(rawJWT), parseOpts...)
	if err != nil {
		return nil, fmt.Errorf("SET signature verification failed: %w", err)
	}

	// Extract SET-specific custom claims from the verified token.
	var raw rawSETClaims
	privateClaims, err := json.Marshal(verified.PrivateClaims())
	if err != nil {
		return nil, fmt.Errorf("failed to marshal SET private claims: %w", err)
	}
	if err := json.Unmarshal(privateClaims, &raw); err != nil {
		return nil, fmt.Errorf("failed to decode SET custom claims: %w", err)
	}

	if len(raw.Events) == 0 {
		return nil, fmt.Errorf("SET contains no events")
	}

	return &SET{
		Issuer:      verified.Issuer(),
		JWTID:       verified.JwtID(),
		TimeOfEvent: raw.TOE,
		Events:      raw.Events,
		SubjectID:   raw.SubjectID,
	}, nil
}

// oidcDiscovery is the minimal subset of an OIDC provider's discovery document
// that we need: just the JWKS URI.
type oidcDiscovery struct {
	JWKSURI string `json:"jwks_uri"`
}

// fetchJWKSURI retrieves the JWKS URI from the OIDC discovery document at
// issuer + "/.well-known/openid-configuration".
func fetchJWKSURI(ctx context.Context, issuer string, httpClient *http.Client) (string, error) {
	discoveryURL := issuer + "/.well-known/openid-configuration"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to build discovery request: %w", err)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to fetch discovery document: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("discovery document returned HTTP %d", resp.StatusCode)
	}

	var doc oidcDiscovery
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return "", fmt.Errorf("failed to decode discovery document: %w", err)
	}
	if doc.JWKSURI == "" {
		return "", fmt.Errorf("discovery document missing jwks_uri")
	}
	return doc.JWKSURI, nil
}
