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
	"testing"
	"time"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"
)

const (
	testIssuer  = "https://accounts.google.com"
	testSubject = "123456789"
)

func newTestStore(t *testing.T) *FileStore {
	t.Helper()
	return &FileStore{
		Fs:   afero.NewMemMapFs(),
		Path: "/test/caep-events",
	}
}

func TestWriteAndRead_BlockingEventAfterIat(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)

	tokenIat := time.Now().Add(-10 * time.Minute)
	eventTime := time.Now().Add(-5 * time.Minute) // after token issuance

	err := store.WriteEvent(StoredEvent{
		Issuer:     testIssuer,
		Subject:    testSubject,
		EventType:  EventSessionRevoked,
		ReceivedAt: eventTime,
	})
	require.NoError(t, err)

	blocked, event, err := store.HasBlockingEvent(testIssuer, testSubject, tokenIat, DefaultBlockingEvents)
	require.NoError(t, err)
	require.True(t, blocked)
	require.NotNil(t, event)
	require.Equal(t, EventSessionRevoked, event.EventType)
}

func TestWriteAndRead_EventBeforeIat_NotBlocking(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)

	eventTime := time.Now().Add(-30 * time.Minute)
	tokenIat := time.Now().Add(-5 * time.Minute) // token issued AFTER the event

	err := store.WriteEvent(StoredEvent{
		Issuer:     testIssuer,
		Subject:    testSubject,
		EventType:  EventSessionRevoked,
		ReceivedAt: eventTime,
	})
	require.NoError(t, err)

	// Event predates the token — must not block a freshly re-issued token.
	blocked, event, err := store.HasBlockingEvent(testIssuer, testSubject, tokenIat, DefaultBlockingEvents)
	require.NoError(t, err)
	require.False(t, blocked)
	require.Nil(t, event)
}

func TestWriteAndRead_DifferentUser_NotBlocking(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)

	tokenIat := time.Now().Add(-10 * time.Minute)

	// Write event for a different subject.
	err := store.WriteEvent(StoredEvent{
		Issuer:     testIssuer,
		Subject:    "other-subject",
		EventType:  EventSessionRevoked,
		ReceivedAt: time.Now(),
	})
	require.NoError(t, err)

	blocked, event, err := store.HasBlockingEvent(testIssuer, testSubject, tokenIat, DefaultBlockingEvents)
	require.NoError(t, err)
	require.False(t, blocked)
	require.Nil(t, event)
}

func TestWriteAndRead_NonBlockingEventType_NotBlocking(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)

	tokenIat := time.Now().Add(-10 * time.Minute)

	// Write an event type that is not in the blocking list.
	err := store.WriteEvent(StoredEvent{
		Issuer:     testIssuer,
		Subject:    testSubject,
		EventType:  EventAccountEnabled, // not in DefaultBlockingEvents
		ReceivedAt: time.Now(),
	})
	require.NoError(t, err)

	blocked, event, err := store.HasBlockingEvent(testIssuer, testSubject, tokenIat, DefaultBlockingEvents)
	require.NoError(t, err)
	require.False(t, blocked)
	require.Nil(t, event)
}

func TestWriteAndRead_NoEvents_NotBlocking(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)

	tokenIat := time.Now().Add(-10 * time.Minute)

	blocked, event, err := store.HasBlockingEvent(testIssuer, testSubject, tokenIat, DefaultBlockingEvents)
	require.NoError(t, err)
	require.False(t, blocked)
	require.Nil(t, event)
}

func TestWriteAndRead_MultipleEvents_FirstBlockingReturned(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)

	tokenIat := time.Now().Add(-10 * time.Minute)

	// Write two events: one non-blocking, one blocking.
	require.NoError(t, store.WriteEvent(StoredEvent{
		Issuer:     testIssuer,
		Subject:    testSubject,
		EventType:  EventAccountEnabled,
		ReceivedAt: time.Now(),
	}))
	require.NoError(t, store.WriteEvent(StoredEvent{
		Issuer:     testIssuer,
		Subject:    testSubject,
		EventType:  EventAccountCompromised,
		ReceivedAt: time.Now(),
	}))

	blocked, event, err := store.HasBlockingEvent(testIssuer, testSubject, tokenIat, DefaultBlockingEvents)
	require.NoError(t, err)
	require.True(t, blocked)
	require.NotNil(t, event)
	require.Equal(t, EventAccountCompromised, event.EventType)
}

func TestWriteAndRead_CustomBlockingList(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)

	tokenIat := time.Now().Add(-10 * time.Minute)

	// EventCredentialChange is not in DefaultBlockingEvents but we add it here.
	customBlocking := []string{EventCredentialChange}

	require.NoError(t, store.WriteEvent(StoredEvent{
		Issuer:     testIssuer,
		Subject:    testSubject,
		EventType:  EventCredentialChange,
		ReceivedAt: time.Now(),
	}))

	blocked, event, err := store.HasBlockingEvent(testIssuer, testSubject, tokenIat, customBlocking)
	require.NoError(t, err)
	require.True(t, blocked)
	require.NotNil(t, event)
}

func TestNewFileStore_DefaultPath(t *testing.T) {
	t.Parallel()
	store := NewFileStore("")
	require.Equal(t, DefaultStorePath, store.Path)
	require.NotNil(t, store.Fs)
}

func TestNewFileStore_CustomPath(t *testing.T) {
	t.Parallel()
	store := NewFileStore("/custom/path")
	require.Equal(t, "/custom/path", store.Path)
}

func TestWriteEvent_MkdirAllError(t *testing.T) {
	t.Parallel()
	// A read-only FS will cause MkdirAll to fail.
	fs := afero.NewReadOnlyFs(afero.NewMemMapFs())
	store := &FileStore{Fs: fs, Path: "/test/caep"}

	err := store.WriteEvent(StoredEvent{
		Issuer:     testIssuer,
		Subject:    testSubject,
		EventType:  EventSessionRevoked,
		ReceivedAt: time.Now(),
	})
	require.Error(t, err)
	require.ErrorContains(t, err, "failed to create event store directory")
}

func TestReadEvents_InvalidJSON(t *testing.T) {
	t.Parallel()
	memFs := afero.NewMemMapFs()
	store := &FileStore{Fs: memFs, Path: "/test/caep"}

	// Create the directory and write invalid JSON directly.
	require.NoError(t, memFs.MkdirAll("/test/caep", 0750))
	filePath := "/test/caep/" + userKey(testIssuer, testSubject)
	require.NoError(t, afero.WriteFile(memFs, filePath, []byte("not valid json"), 0640))

	_, _, err := store.HasBlockingEvent(testIssuer, testSubject, time.Now().Add(-1*time.Hour), DefaultBlockingEvents)
	require.Error(t, err)
	require.ErrorContains(t, err, "failed to parse events file")
}
