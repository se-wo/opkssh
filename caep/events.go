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

import "time"

// CAEP event type URNs as defined by the OpenID Continuous Access Evaluation
// Profile specification.
// https://openid.net/specs/openid-caep-1_0-final.html
const (
	EventSessionRevoked         = "https://schemas.openid.net/secevent/caep/event-type/session-revoked"
	EventCredentialChange       = "https://schemas.openid.net/secevent/caep/event-type/credential-change"
	EventAssuranceLevelChange   = "https://schemas.openid.net/secevent/caep/event-type/assurance-level-change"
	EventTokenClaimsChange      = "https://schemas.openid.net/secevent/caep/event-type/token-claims-change"
	EventDeviceComplianceChange = "https://schemas.openid.net/secevent/caep/event-type/device-compliance-change"
)

// RISC event type URNs as defined by the OpenID Risk Incident Sharing and
// Coordination specification.
// https://openid.net/specs/openid-risc-1_0-final.html
const (
	EventAccountDisabled       = "https://schemas.openid.net/secevent/risc/event-type/account-disabled"
	EventAccountEnabled        = "https://schemas.openid.net/secevent/risc/event-type/account-enabled"
	EventAccountPurged         = "https://schemas.openid.net/secevent/risc/event-type/account-purged"
	EventAccountCompromised    = "https://schemas.openid.net/secevent/risc/event-type/account-compromised"
	EventCredentialCompromised = "https://schemas.openid.net/secevent/risc/event-type/credential-compromise"
	EventOptIn                 = "https://schemas.openid.net/secevent/risc/event-type/opt-in"
	EventOptOut                = "https://schemas.openid.net/secevent/risc/event-type/opt-out"
)

// DefaultBlockingEvents is the set of CAEP/RISC events that block SSH login
// when no explicit blocking_events list is configured. These represent
// definitive revocation or compromise of the user's session or credentials.
var DefaultBlockingEvents = []string{
	EventSessionRevoked,
	EventAccountDisabled,
	EventAccountPurged,
	EventAccountCompromised,
	EventCredentialCompromised,
}

// StoredEvent is a CAEP or RISC security event persisted to the local event
// store after being received from an SSF transmitter's polling endpoint.
type StoredEvent struct {
	Issuer      string    `json:"iss"`
	Subject     string    `json:"sub"`
	EventType   string    `json:"event_type"`
	ReceivedAt  time.Time `json:"received_at"` // wall-clock time opkssh received/stored this event
	TimeOfEvent int64     `json:"toe"`         // Unix time from SET "toe" claim; 0 if not present
}
