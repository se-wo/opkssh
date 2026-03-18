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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"time"

	"github.com/spf13/afero"
	"golang.org/x/exp/slices"
)

// DefaultStorePath is the default filesystem path for the local CAE event
// store. This directory must be owned by opksshuser (the
// AuthorizedKeysCommandUser) since opkssh verify both writes (during SSF
// polling) and reads (during CAE evaluation) this store.
const DefaultStorePath = "/var/lib/opk/caep-events"

// FileStore persists CAEP/RISC events to disk. Events are stored as JSON
// files keyed by a hash of the user's (issuer, subject) pair so that login-
// time lookups are O(1) file reads.
//
// Directory permissions: 0750 owned by opksshuser.
// File permissions: 0640 owned by opksshuser.
type FileStore struct {
	Fs   afero.Fs
	Path string
}

// NewFileStore returns a FileStore rooted at path (default: DefaultStorePath).
func NewFileStore(path string) *FileStore {
	if path == "" {
		path = DefaultStorePath
	}
	return &FileStore{
		Fs:   afero.NewOsFs(),
		Path: path,
	}
}

// userKey returns the filename (without directory) used to store events for
// the given (issuer, subject) pair. Uses a SHA-256 hex digest to produce a
// safe, fixed-length filename that does not expose PII in directory listings.
func userKey(iss, sub string) string {
	h := sha256.Sum256([]byte(iss + ":" + sub))
	return hex.EncodeToString(h[:]) + ".json"
}

// WriteEvent persists a single StoredEvent for its (Issuer, Subject) pair.
// Existing events for the same user are preserved; the new event is appended.
// The store directory is created if it does not exist.
func (s *FileStore) WriteEvent(event StoredEvent) error {
	if err := s.Fs.MkdirAll(s.Path, fs.FileMode(0750)); err != nil {
		return fmt.Errorf("failed to create event store directory: %w", err)
	}

	filePath := s.Path + "/" + userKey(event.Issuer, event.Subject)

	existing, err := s.readEvents(filePath)
	if err != nil {
		return err
	}

	existing = append(existing, event)

	data, err := json.Marshal(existing)
	if err != nil {
		return fmt.Errorf("failed to marshal events: %w", err)
	}

	if err := afero.WriteFile(s.Fs, filePath, data, fs.FileMode(0640)); err != nil {
		return fmt.Errorf("failed to write events file: %w", err)
	}
	return nil
}

// HasBlockingEvent returns (true, event, nil) if the event store contains any
// event whose type is in blockingTypes and whose ReceivedAt timestamp is
// strictly after tokenIssuedAt. This ensures that events that predate the
// current token do not block a legitimately re-issued token.
//
// Returns (false, nil, nil) if no blocking event is found.
// Returns (false, nil, err) if the store is inaccessible.
func (s *FileStore) HasBlockingEvent(iss, sub string, tokenIssuedAt time.Time, blockingTypes []string) (bool, *StoredEvent, error) {
	filePath := s.Path + "/" + userKey(iss, sub)

	events, err := s.readEvents(filePath)
	if err != nil {
		return false, nil, err
	}

	for i := range events {
		ev := &events[i]
		if !slices.Contains(blockingTypes, ev.EventType) {
			continue
		}
		// Only block if the event was received after the token was issued.
		// This avoids blocking a freshly re-issued token due to a stale event.
		if ev.ReceivedAt.After(tokenIssuedAt) {
			return true, ev, nil
		}
	}
	return false, nil, nil
}

// readEvents reads the JSON event array from filePath. Returns an empty slice
// if the file does not exist (not an error — no events recorded yet).
func (s *FileStore) readEvents(filePath string) ([]StoredEvent, error) {
	data, err := afero.ReadFile(s.Fs, filePath)
	if err != nil {
		if isNotExist(err) {
			return []StoredEvent{}, nil
		}
		return nil, fmt.Errorf("failed to read events file: %w", err)
	}

	var events []StoredEvent
	if err := json.Unmarshal(data, &events); err != nil {
		return nil, fmt.Errorf("failed to parse events file: %w", err)
	}
	return events, nil
}

func isNotExist(err error) bool {
	return os.IsNotExist(err)
}
