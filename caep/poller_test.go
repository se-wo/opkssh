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
	"net/http"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"
)

// pollerCfg builds a PollerConfig pointing at the setServer's /poll endpoint.
func pollerCfg(ss *setServer, audience string) PollerConfig {
	return PollerConfig{
		Issuer:          ss.URL,
		PollingEndpoint: ss.URL + "/poll",
		StreamToken:     "test-token",
		Audience:        audience,
	}
}

// signSETWithSubID signs a SET JWT using the setServer's key but with a custom
// sub_id map. This is useful for testing unresolvable subject formats.
func (ss *setServer) signSETWithSubID(t *testing.T, events map[string]interface{}, subID map[string]interface{}) string {
	t.Helper()
	tok := jwt.New()
	require.NoError(t, tok.Set(jwt.IssuerKey, ss.URL))
	require.NoError(t, tok.Set(jwt.JwtIDKey, "test-jti"))
	require.NoError(t, tok.Set("events", events))
	require.NoError(t, tok.Set("sub_id", subID))
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256, ss.privKey))
	require.NoError(t, err)
	return string(signed)
}

func TestPoll_NoEvents_HTTP204(t *testing.T) {
	t.Parallel()
	ss := newSETServer(t)
	// Default /poll handler returns 204 — no events.

	store := &FileStore{Fs: afero.NewMemMapFs(), Path: "/test/caep"}
	poller := NewPoller(store, ss.Client(), nil)

	err := poller.Poll(context.Background(), pollerCfg(ss, ""))
	require.NoError(t, err)

	// Confirm nothing was stored.
	blocked, _, err := store.HasBlockingEvent(ss.URL, testSubject, time.Now().Add(-1*time.Hour), DefaultBlockingEvents)
	require.NoError(t, err)
	require.False(t, blocked)
}

func TestPoll_HTTP401_ReturnsError(t *testing.T) {
	t.Parallel()
	ss := newSETServer(t)
	ss.setPollHandler(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})

	store := &FileStore{Fs: afero.NewMemMapFs(), Path: "/test/caep"}
	poller := NewPoller(store, ss.Client(), nil)

	err := poller.Poll(context.Background(), pollerCfg(ss, ""))
	require.Error(t, err)
	require.ErrorContains(t, err, "HTTP 401")
}

func TestPoll_ValidSET_StoresBlockingEvent(t *testing.T) {
	t.Parallel()
	ss := newSETServer(t)

	events := map[string]interface{}{
		EventSessionRevoked: map[string]interface{}{},
	}
	rawJWT := ss.signSET(t, testSubject, "", events)

	ss.setPollHandler(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(pollResponseJSON(t, map[string]string{"jti-1": rawJWT}, false)) //nolint:errcheck
	})

	store := &FileStore{Fs: afero.NewMemMapFs(), Path: "/test/caep"}
	poller := NewPoller(store, ss.Client(), DefaultBlockingEvents)

	err := poller.Poll(context.Background(), pollerCfg(ss, ""))
	require.NoError(t, err)

	// The event must have been written.
	tokenIat := time.Now().Add(-1 * time.Hour)
	blocked, ev, err := store.HasBlockingEvent(ss.URL, testSubject, tokenIat, DefaultBlockingEvents)
	require.NoError(t, err)
	require.True(t, blocked)
	require.Equal(t, EventSessionRevoked, ev.EventType)
}

func TestPoll_MoreAvailable_ReturnsNil(t *testing.T) {
	t.Parallel()
	ss := newSETServer(t)

	events := map[string]interface{}{
		EventSessionRevoked: map[string]interface{}{},
	}
	rawJWT := ss.signSET(t, testSubject, "", events)

	ss.setPollHandler(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// moreAvailable=true — should be non-fatal.
		w.Write(pollResponseJSON(t, map[string]string{"jti-1": rawJWT}, true)) //nolint:errcheck
	})

	store := &FileStore{Fs: afero.NewMemMapFs(), Path: "/test/caep"}
	poller := NewPoller(store, ss.Client(), nil)

	// moreAvailable being true is informational only — Poll must still succeed.
	err := poller.Poll(context.Background(), pollerCfg(ss, ""))
	require.NoError(t, err)
}

func TestPoll_MalformedSET_Skipped(t *testing.T) {
	t.Parallel()
	ss := newSETServer(t)

	ss.setPollHandler(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Return a SET that is not a valid JWT — should be skipped, not cause an error.
		w.Write(pollResponseJSON(t, map[string]string{"jti-bad": "not.a.valid.jwt"}, false)) //nolint:errcheck
	})

	store := &FileStore{Fs: afero.NewMemMapFs(), Path: "/test/caep"}
	poller := NewPoller(store, ss.Client(), nil)

	err := poller.Poll(context.Background(), pollerCfg(ss, ""))
	require.NoError(t, err)

	// Nothing stored.
	blocked, _, err := store.HasBlockingEvent(ss.URL, testSubject, time.Now().Add(-1*time.Hour), DefaultBlockingEvents)
	require.NoError(t, err)
	require.False(t, blocked)
}

func TestPoll_UnresolvableSubject_Skipped(t *testing.T) {
	t.Parallel()
	ss := newSETServer(t)

	events := map[string]interface{}{EventSessionRevoked: map[string]interface{}{}}
	// Use a "phone_number" sub_id format with no "sub" field so resolveSubject
	// returns "", "" and the event is skipped.
	rawJWT := ss.signSETWithSubID(t, events, map[string]interface{}{
		"format": "phone_number",
		"phone":  "+1-555-0100",
	})

	ss.setPollHandler(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(pollResponseJSON(t, map[string]string{"jti-1": rawJWT}, false)) //nolint:errcheck
	})

	store := &FileStore{Fs: afero.NewMemMapFs(), Path: "/test/caep"}
	poller := NewPoller(store, ss.Client(), nil)

	err := poller.Poll(context.Background(), pollerCfg(ss, ""))
	require.NoError(t, err)

	// Nothing stored because subject is unresolvable.
	blocked, _, err := store.HasBlockingEvent(ss.URL, testSubject, time.Now().Add(-1*time.Hour), DefaultBlockingEvents)
	require.NoError(t, err)
	require.False(t, blocked)
}

func TestPoll_AcknowledgeFailure_NonFatal(t *testing.T) {
	t.Parallel()
	ss := newSETServer(t)

	events := map[string]interface{}{EventSessionRevoked: map[string]interface{}{}}
	rawJWT := ss.signSET(t, testSubject, "", events)

	callCount := 0
	ss.setPollHandler(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if callCount == 1 {
			// First call: return the SET.
			w.Header().Set("Content-Type", "application/json")
			w.Write(pollResponseJSON(t, map[string]string{"jti-1": rawJWT}, false)) //nolint:errcheck
			return
		}
		// Second call (acknowledge): return an error — should be non-fatal.
		w.WriteHeader(http.StatusInternalServerError)
	})

	store := &FileStore{Fs: afero.NewMemMapFs(), Path: "/test/caep"}
	poller := NewPoller(store, ss.Client(), nil)

	// Even though acknowledge fails, Poll must return nil (ack failure is non-fatal).
	err := poller.Poll(context.Background(), pollerCfg(ss, ""))
	require.NoError(t, err)

	// The event was still stored before the failed ack.
	blocked, _, err := store.HasBlockingEvent(ss.URL, testSubject, time.Now().Add(-1*time.Hour), DefaultBlockingEvents)
	require.NoError(t, err)
	require.True(t, blocked)
}

func TestNewPoller_DefaultBlockingEvents(t *testing.T) {
	t.Parallel()
	store := &FileStore{Fs: afero.NewMemMapFs(), Path: "/test/caep"}

	// nil blockingEvents → DefaultBlockingEvents used.
	p := NewPoller(store, nil, nil)
	require.Equal(t, DefaultBlockingEvents, p.BlockingEvents)
	require.NotNil(t, p.HttpClient)
}

func TestResolveSubject_IssSubFormat(t *testing.T) {
	t.Parallel()
	set := &SET{
		Issuer: "https://issuer.example.com",
		SubjectID: SubjectID{
			Format:  "iss_sub",
			Issuer:  "https://issuer.example.com",
			Subject: "user-123",
		},
	}
	iss, sub := resolveSubject(set)
	require.Equal(t, "https://issuer.example.com", iss)
	require.Equal(t, "user-123", sub)
}

func TestResolveSubject_OpaqueFormat(t *testing.T) {
	t.Parallel()
	set := &SET{
		Issuer: "https://issuer.example.com",
		SubjectID: SubjectID{
			Format:  "opaque",
			Subject: "opaque-id-xyz",
		},
	}
	iss, sub := resolveSubject(set)
	require.Equal(t, "https://issuer.example.com", iss)
	require.Equal(t, "opaque-id-xyz", sub)
}

func TestResolveSubject_FallbackWithSubject(t *testing.T) {
	t.Parallel()
	set := &SET{
		Issuer: "https://issuer.example.com",
		SubjectID: SubjectID{
			Format:  "unknown",
			Subject: "some-subject",
		},
	}
	iss, sub := resolveSubject(set)
	require.Equal(t, "https://issuer.example.com", iss)
	require.Equal(t, "some-subject", sub)
}

func TestResolveSubject_NoSubject_ReturnsEmpty(t *testing.T) {
	t.Parallel()
	set := &SET{
		Issuer: "https://issuer.example.com",
		SubjectID: SubjectID{
			Format: "phone_number",
			// No Subject field.
		},
	}
	iss, sub := resolveSubject(set)
	require.Equal(t, "", iss)
	require.Equal(t, "", sub)
}
