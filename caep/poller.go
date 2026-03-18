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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
)

// Poller fetches queued Security Event Tokens (SETs) from an SSF transmitter's
// polling endpoint (RFC 8936), extracts blocking CAEP/RISC events, and
// persists them to the local FileStore for login-time evaluation.
//
// Polling happens synchronously inside opkssh verify — no background daemon.
type Poller struct {
	Store          *FileStore
	HttpClient     *http.Client
	BlockingEvents []string
}

// NewPoller creates a Poller with the given store and optional custom
// http.Client. If httpClient is nil, http.DefaultClient is used.
func NewPoller(store *FileStore, httpClient *http.Client, blockingEvents []string) *Poller {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	if len(blockingEvents) == 0 {
		blockingEvents = DefaultBlockingEvents
	}
	return &Poller{
		Store:          store,
		HttpClient:     httpClient,
		BlockingEvents: blockingEvents,
	}
}

// PollerConfig holds per-issuer SSF stream configuration. These values are
// obtained by the admin when registering an SSF stream with the provider via
// the Stream Management API.
type PollerConfig struct {
	// Issuer is the OIDC issuer URI; used to verify the "iss" claim in SETs.
	Issuer string
	// PollingEndpoint is the transmitter's RFC 8936 polling endpoint URL.
	PollingEndpoint string
	// StreamToken is the bearer token used to authenticate requests to the
	// polling endpoint (obtained during stream registration).
	StreamToken string
	// Audience is the expected "aud" claim in received SETs. Typically this
	// is the URL this application registered as its receiver identifier.
	Audience string
}

// pollRequest is the JSON body sent to the transmitter's polling endpoint
// per RFC 8936 §2.1.
type pollRequest struct {
	// MaxEvents limits how many SETs the transmitter returns per request.
	// Zero means no limit (use transmitter's default).
	MaxEvents int `json:"maxEvents,omitempty"`
	// Acknowledge contains jti values of SETs to acknowledge (delete from queue).
	Acknowledge []string `json:"ack,omitempty"`
	// ReturnImmediately controls whether to return immediately even if no
	// events are available (vs. long-polling). We always use true since we
	// poll synchronously at login time.
	ReturnImmediately bool `json:"returnImmediately"`
}

// pollResponse is the JSON body returned by the transmitter's polling endpoint
// per RFC 8936 §2.2.
type pollResponse struct {
	// Sets maps each jti to a raw SET JWT string.
	Sets map[string]string `json:"sets"`
	// MoreAvailable indicates whether more SETs are queued after this batch.
	MoreAvailable bool `json:"moreAvailable"`
}

// Poll fetches queued SETs from the transmitter's polling endpoint, stores any
// blocking CAEP/RISC events in the local FileStore, and acknowledges receipt
// so the transmitter can remove them from the queue.
//
// If the polling endpoint is unreachable or returns an error, Poll returns an
// error. Callers should apply cfg.FailOpen logic to decide whether to block
// login on poll failure.
//
// Poll fetches at most one batch of events. If moreAvailable is true in the
// response, subsequent logins will retrieve the remaining events. This ensures
// poll latency stays bounded at login time.
func (p *Poller) Poll(ctx context.Context, cfg PollerConfig) error {
	reqBody := pollRequest{
		ReturnImmediately: true,
	}
	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("failed to marshal poll request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.PollingEndpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return fmt.Errorf("failed to build poll request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+cfg.StreamToken)

	resp, err := p.HttpClient.Do(req)
	if err != nil {
		return fmt.Errorf("SSF poll request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNoContent {
		// No events queued — nothing to do.
		return nil
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("SSF poll endpoint returned HTTP %d", resp.StatusCode)
	}

	var pollResp pollResponse
	if err := json.NewDecoder(resp.Body).Decode(&pollResp); err != nil {
		return fmt.Errorf("failed to decode poll response: %w", err)
	}

	var toAck []string
	for jti, rawJWT := range pollResp.Sets {
		set, err := ParseAndVerify(ctx, rawJWT, cfg.Issuer, cfg.Audience, p.HttpClient)
		if err != nil {
			// Log and skip malformed SETs; don't fail the whole poll.
			log.Printf("CAE: skipping malformed SET (jti=%s): %v", jti, err)
			continue
		}

		if err := p.storeBlockingEvents(set); err != nil {
			log.Printf("CAE: failed to store events from SET (jti=%s): %v", jti, err)
			// Don't acknowledge a SET we failed to store — we'll retry next login.
			continue
		}
		toAck = append(toAck, jti)
	}

	// Acknowledge the SETs we successfully processed.
	if len(toAck) > 0 {
		if err := p.acknowledge(ctx, cfg, toAck); err != nil {
			// Non-fatal: we've stored the events; worst case is we re-process
			// the same SETs on the next login (idempotent write).
			log.Printf("CAE: failed to acknowledge %d SETs: %v", len(toAck), err)
		}
	}

	if pollResp.MoreAvailable {
		log.Println("CAE: more events available at polling endpoint; they will be retrieved on the next login")
	}

	return nil
}

// storeBlockingEvents iterates the events in a SET and persists any that are
// in the configured blocking list.
func (p *Poller) storeBlockingEvents(set *SET) error {
	iss, sub := resolveSubject(set)
	if iss == "" || sub == "" {
		// Can't identify the user — log and skip.
		log.Printf("CAE: SET (jti=%s) has unresolvable subject, skipping", set.JWTID)
		return nil
	}

	for eventType := range set.Events {
		stored := StoredEvent{
			Issuer:      iss,
			Subject:     sub,
			EventType:   eventType,
			ReceivedAt:  time.Now().UTC(),
			TimeOfEvent: set.TimeOfEvent,
		}
		if err := p.Store.WriteEvent(stored); err != nil {
			return fmt.Errorf("failed to write event %q: %w", eventType, err)
		}
		log.Printf("CAE: stored event type=%q iss=%q sub=%q", eventType, iss, sub)
	}
	return nil
}

// acknowledge sends an acknowledgement request to the transmitter's polling
// endpoint so it can remove successfully processed SETs from the queue.
func (p *Poller) acknowledge(ctx context.Context, cfg PollerConfig, jtis []string) error {
	ackBody := pollRequest{
		Acknowledge:       jtis,
		ReturnImmediately: true,
	}
	bodyBytes, err := json.Marshal(ackBody)
	if err != nil {
		return fmt.Errorf("failed to marshal ack request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.PollingEndpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return fmt.Errorf("failed to build ack request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+cfg.StreamToken)

	resp, err := p.HttpClient.Do(req)
	if err != nil {
		return fmt.Errorf("ack request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("ack endpoint returned HTTP %d", resp.StatusCode)
	}
	return nil
}

// resolveSubject extracts the (issuer, subject) pair from a SET's sub_id.
// Supports "iss_sub" format (most common for CAEP/RISC) and falls back to
// the SET's own issuer when only a subject is present.
func resolveSubject(set *SET) (iss, sub string) {
	sid := set.SubjectID
	switch sid.Format {
	case "iss_sub":
		return sid.Issuer, sid.Subject
	case "opaque":
		// Opaque subjects are provider-specific; use SET issuer + subject.
		return set.Issuer, sid.Subject
	default:
		if sid.Subject != "" {
			return set.Issuer, sid.Subject
		}
	}
	return "", ""
}
