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

package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

// ServerConfig struct to represent the /etc/opk/config.yml file that runs on the server that the user is SSHing into
type ServerConfig struct {
	EnvVars    map[string]string `yaml:"env_vars"`
	DenyUsers  []string          `yaml:"deny_users"`
	DenyEmails []string          `yaml:"deny_emails"`
	// CAE configures Continuous Access Evaluation via SSF polling.
	// If nil or Enabled is false, CAE evaluation is skipped entirely.
	CAE *CAEConfig `yaml:"cae,omitempty"`
}

// CAEConfig configures login-time Continuous Access Evaluation using the
// OpenID Shared Signals Framework polling delivery model (RFC 8936).
//
// When enabled, opkssh verify polls each configured SSF stream at login time
// to retrieve queued CAEP/RISC security events. Events are persisted to a
// local store and checked against the authenticating user's (iss, sub) pair.
// Login is denied if any blocking event was received after the PK token's
// "iat" claim.
//
// Admin one-time setup: register an SSF stream with each OIDC provider using
// the provider's Stream Management API, selecting the polling delivery method.
// Record the resulting polling endpoint URL and stream bearer token here.
type CAEConfig struct {
	// Enabled must be true for CAE evaluation to take effect.
	Enabled bool `yaml:"enabled"`

	// FailOpen controls behaviour when the local event store or the SSF
	// polling endpoint is unavailable:
	//   false (default): deny login and log the error (fail-closed / secure default)
	//   true:            log a warning and allow login (fail-open / availability-first)
	FailOpen bool `yaml:"fail_open"`

	// EventStorePath is the directory where received CAEP/RISC events are
	// persisted. Defaults to /var/lib/opk/caep-events if empty.
	// Must be readable and writable by opksshuser (the AuthorizedKeysCommandUser).
	EventStorePath string `yaml:"event_store_path"`

	// EventTTLDays is how many days a stored CAEP/RISC event is retained before
	// being pruned. Events older than this cannot block any valid token anyway,
	// since tokens expire before the TTL elapses. 0 means the default (30 days).
	EventTTLDays int `yaml:"event_ttl_days"`

	// BlockingEvents is the list of CAEP/RISC event type URIs that trigger a
	// login denial. If empty, caep.DefaultBlockingEvents is used.
	BlockingEvents []string `yaml:"blocking_events"`

	// Streams holds per-issuer SSF stream configuration. Each entry
	// corresponds to a stream registered with one OIDC provider.
	Streams []CAEStreamConfig `yaml:"streams"`
}

// CAEStreamConfig holds the SSF stream parameters for a single OIDC provider.
// These values are obtained when the admin registers an SSF stream with the
// provider via its Stream Management API.
type CAEStreamConfig struct {
	// Issuer is the OIDC issuer URI (must match the "iss" claim in tokens
	// from this provider, e.g. "https://accounts.google.com").
	Issuer string `yaml:"issuer"`

	// PollingEndpoint is the transmitter's RFC 8936 polling endpoint URL.
	// Example: "https://risc.googleapis.com/v1beta/events:poll"
	PollingEndpoint string `yaml:"polling_endpoint"`

	// StreamToken is the bearer token used to authenticate requests to the
	// polling endpoint. Treat as a secret; restrict file permissions on
	// /etc/opk/config.yml accordingly (0640, root:opksshuser).
	StreamToken string `yaml:"stream_token"`

	// Audience is the expected "aud" claim in received SETs. Typically this
	// is the URL the admin registered as the receiver identifier when setting
	// up the SSF stream (e.g. "https://ssh.example.com").
	Audience string `yaml:"audience"`
}

func NewServerConfig(c []byte) (*ServerConfig, error) {
	var serverConfig ServerConfig
	if err := yaml.Unmarshal(c, &serverConfig); err != nil {
		return nil, err
	}

	return &serverConfig, nil
}

func (c *ServerConfig) SetEnvVars() error {
	for k, v := range c.EnvVars {
		if err := os.Setenv(k, v); err != nil {
			return err
		}
	}
	return nil
}
