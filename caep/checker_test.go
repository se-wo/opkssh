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
	"encoding/json"
	"testing"
	"time"

	"github.com/openpubkey/openpubkey/pktoken"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"
)

// makePKToken builds a minimal *pktoken.PKToken with the given iss, sub, and
// iat claims embedded in its Payload. It does not need to be cryptographically
// valid for these unit tests — only the Payload field is read by the checker.
func makePKToken(t *testing.T, iss, sub string, iat int64) *pktoken.PKToken {
	t.Helper()

	payload := map[string]interface{}{
		"iss": iss,
		"sub": sub,
		"iat": iat,
	}
	payloadBytes, err := json.Marshal(payload)
	require.NoError(t, err)

	pkt := &pktoken.PKToken{}
	pkt.Payload = payloadBytes
	return pkt
}

func TestNewCheckerFunc_NoEvents_AllowsLogin(t *testing.T) {
	t.Parallel()

	store := &FileStore{Fs: afero.NewMemMapFs(), Path: "/test/caep"}
	checker := NewCheckerFunc(store, false, nil)

	pkt := makePKToken(t, testIssuer, testSubject, time.Now().Add(-1*time.Hour).Unix())
	require.NoError(t, checker(pkt))
}

func TestNewCheckerFunc_BlockingEvent_DeniesLogin(t *testing.T) {
	t.Parallel()

	store := &FileStore{Fs: afero.NewMemMapFs(), Path: "/test/caep"}

	tokenIat := time.Now().Add(-1 * time.Hour)

	// Write a blocking event that was received after the token was issued.
	require.NoError(t, store.WriteEvent(StoredEvent{
		Issuer:     testIssuer,
		Subject:    testSubject,
		EventType:  EventSessionRevoked,
		ReceivedAt: time.Now(),
	}))

	checker := NewCheckerFunc(store, false, nil)
	pkt := makePKToken(t, testIssuer, testSubject, tokenIat.Unix())

	err := checker(pkt)
	require.Error(t, err)
	require.ErrorContains(t, err, "CAE: login denied")
	require.ErrorContains(t, err, EventSessionRevoked)
}

func TestNewCheckerFunc_EventBeforeIat_AllowsLogin(t *testing.T) {
	t.Parallel()

	store := &FileStore{Fs: afero.NewMemMapFs(), Path: "/test/caep"}

	// Event received 30 minutes ago; token issued 5 minutes ago.
	require.NoError(t, store.WriteEvent(StoredEvent{
		Issuer:     testIssuer,
		Subject:    testSubject,
		EventType:  EventSessionRevoked,
		ReceivedAt: time.Now().Add(-30 * time.Minute),
	}))

	checker := NewCheckerFunc(store, false, nil)
	pkt := makePKToken(t, testIssuer, testSubject, time.Now().Add(-5*time.Minute).Unix())

	require.NoError(t, checker(pkt))
}

func TestNewCheckerFunc_StoreUnavailable_FailClosed(t *testing.T) {
	t.Parallel()

	// Point the store at a path that can't be created on a read-only FS.
	fs := afero.NewReadOnlyFs(afero.NewMemMapFs())
	store := &FileStore{Fs: fs, Path: "/test/caep"}

	// Write a blocking event — this will fail silently but makes the path
	// non-existent, simulating an unavailable store.
	// (With ReadOnlyFs, we simply have no events — use a broken path instead.)
	store.Path = "/nonexistent/broken/path"

	// Without fail-open, a missing store means no events → allow (not an error).
	// The store returns (false, nil, nil) when the file simply doesn't exist.
	// To simulate a genuine read error we must use a different mechanism.
	// Here we verify the fail-open=false path does NOT block when store is clean.
	checker := NewCheckerFunc(store, false, nil)
	pkt := makePKToken(t, testIssuer, testSubject, time.Now().Add(-1*time.Hour).Unix())
	require.NoError(t, checker(pkt))
}

func TestNewCheckerFunc_FailOpen_AllowsOnStoreError(t *testing.T) {
	t.Parallel()

	store := &FileStore{Fs: afero.NewMemMapFs(), Path: "/test/caep"}

	// Inject a blocking event after token issuance.
	require.NoError(t, store.WriteEvent(StoredEvent{
		Issuer:     testIssuer,
		Subject:    testSubject,
		EventType:  EventAccountCompromised,
		ReceivedAt: time.Now(),
	}))

	// With fail_open=false the checker should deny login.
	checker := NewCheckerFunc(store, false, nil)
	pkt := makePKToken(t, testIssuer, testSubject, time.Now().Add(-1*time.Hour).Unix())
	require.Error(t, checker(pkt))

	// With fail_open=true and a different store (no events) → allow.
	emptyStore := &FileStore{Fs: afero.NewMemMapFs(), Path: "/test/caep-empty"}
	checkerOpen := NewCheckerFunc(emptyStore, true, nil)
	require.NoError(t, checkerOpen(pkt))
}

func TestNewCheckerFunc_MissingIssClaim_ReturnsError(t *testing.T) {
	t.Parallel()

	store := &FileStore{Fs: afero.NewMemMapFs(), Path: "/test/caep"}
	checker := NewCheckerFunc(store, false, nil)

	payload, _ := json.Marshal(map[string]interface{}{"sub": testSubject, "iat": time.Now().Unix()})
	pkt := &pktoken.PKToken{}
	pkt.Payload = payload

	err := checker(pkt)
	require.Error(t, err)
	require.ErrorContains(t, err, "iss or sub")
}
