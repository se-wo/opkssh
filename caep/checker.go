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
	"fmt"
	"log"
	"time"

	"github.com/openpubkey/openpubkey/pktoken"
)

// CAECheckerFunc returns nil if the SSH login is permitted by CAE evaluation,
// or a non-nil error describing the blocking event if it should be denied.
//
// A nil CAECheckerFunc means CAE is disabled; opkssh verify treats nil as
// "allow". This mirrors the PolicyEnforcerFunc injection pattern in verify.go.
type CAECheckerFunc func(pkt *pktoken.PKToken) error

// tokenPayloadClaims extracts the minimal set of claims needed for CAE
// evaluation from a PK token payload.
type tokenPayloadClaims struct {
	Issuer   string `json:"iss"`
	Subject  string `json:"sub"`
	IssuedAt int64  `json:"iat"`
}

// CAEConfig is a subset of the server config used by the checker. It is
// defined here to avoid an import cycle with the config package; the caller
// (verify.go) passes it in.
type CAEConfig interface {
	IsFailOpen() bool
	GetBlockingEvents() []string
}

// NewCheckerFunc returns a CAECheckerFunc that queries the given FileStore to
// determine whether any blocking CAEP/RISC events have been received for the
// authenticating user since their PK token was issued.
//
// failOpen controls behaviour when the store is unavailable:
//   - false (default): deny login and log the error
//   - true: log a warning and allow login
//
// blockingEvents is the set of event type URIs that block login. If empty,
// DefaultBlockingEvents is used.
func NewCheckerFunc(store *FileStore, failOpen bool, blockingEvents []string) CAECheckerFunc {
	if len(blockingEvents) == 0 {
		blockingEvents = DefaultBlockingEvents
	}

	return func(pkt *pktoken.PKToken) error {
		var claims tokenPayloadClaims
		if err := json.Unmarshal(pkt.Payload, &claims); err != nil {
			return fmt.Errorf("CAE: failed to parse PK token payload: %w", err)
		}

		if claims.Issuer == "" || claims.Subject == "" {
			return fmt.Errorf("CAE: PK token missing iss or sub claim")
		}

		tokenIssuedAt := time.Unix(claims.IssuedAt, 0)

		blocked, event, err := store.HasBlockingEvent(claims.Issuer, claims.Subject, tokenIssuedAt, blockingEvents)
		if err != nil {
			if failOpen {
				log.Printf("CAE: store unavailable (fail-open), allowing login: %v", err)
				return nil
			}
			return fmt.Errorf("CAE: event store unavailable: %w", err)
		}

		if blocked {
			return fmt.Errorf("CAE: login denied due to security event %q received at %s",
				event.EventType, event.ReceivedAt.Format(time.RFC3339))
		}

		return nil
	}
}
