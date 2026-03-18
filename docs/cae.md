# Continuous Access Evaluation (CAE)

Continuous Access Evaluation (CAE) lets opkssh deny an SSH login based on
security events emitted by the OIDC provider — even when the user's token
has not yet expired.

Without CAE, a token issued with a one-week expiry remains valid for up to
a week even if the user's account is disabled, their session is revoked, or
their credentials are compromised at the provider.
CAE closes this gap at the moment of login.

## How it works

opkssh implements CAE using the
[OpenID Shared Signals Framework (SSF)](https://openid.net/specs/openid-sharedsignals-framework-1_0-final.html)
**polling delivery model** ([RFC 8936](https://www.rfc-editor.org/rfc/rfc8936)).

At each SSH login attempt, `opkssh verify` (running as `opksshuser`):

1. Calls the provider's SSF polling endpoint to fetch any queued
   Security Event Tokens (SETs).
2. Parses and verifies each SET (JWT signature checked against the
   provider's JWKS).
3. Writes blocking events to a local event store
   (`/var/lib/opk/caep-events/`).
4. Checks whether any blocking event was received **after** the PK token's
   `iat` (issued-at) claim. Events predating the current token do not block
   a freshly re-issued credential.
5. Denies the login if a blocking event is found.

No background daemon is required. All polling happens synchronously inside
`opkssh verify`.

### Blocking events

By default, any of the following event types will block login:

| Event type | Specification |
|------------|---------------|
| `session-revoked` | [CAEP §3.1](https://openid.net/specs/openid-caep-1_0-final.html) |
| `account-disabled` | [RISC §2.2](https://openid.net/specs/openid-risc-1_0-final.html) |
| `account-purged` | RISC §2.3 |
| `account-compromised` | RISC §2.6 |
| `credential-compromise` | RISC §2.7 |

The list is configurable; see [Server configuration](#server-configuration).

## Provider support

SSF polling requires the OIDC provider to expose an SSF transmitter endpoint
(RFC 8936). Not all providers currently support this.

| Provider | SSF polling | Notes |
|----------|:-----------:|-------|
| **Okta** | ✅ | Full SSF transmitter support. Works today. |
| **Microsoft Entra ID** | ⏳ | SSF transmitter preview; app registration requires CP1 capability. See [Azure setup](#microsoft-azure--entra-id). |
| **Google Workspace / consumer** | ❌ | Google supports RISC but only via push delivery, not polling. |
| **GitLab** | ❌ | No SSF support. |
| **GitHub Actions** | ❌ | No SSF support. |

> [!NOTE]
> The SSF specifications reached final status in September 2025.
> Provider support is expanding; check your provider's documentation for
> the latest availability.

---

## Server configuration

CAE is configured in `/etc/opk/config.yml`. It is **disabled by default**;
you must opt in explicitly.

### Minimal configuration

```yaml
cae:
  enabled: true
  streams:
    - issuer: https://your-provider.example.com
      polling_endpoint: https://your-provider.example.com/ssf/events
      stream_token: <bearer-token-from-stream-registration>
      audience: https://your-ssh-server.example.com
```

### Full configuration reference

```yaml
cae:
  # Set to true to enable CAE evaluation at login.
  enabled: true

  # fail_open controls what happens when the event store or the SSF polling
  # endpoint is unavailable:
  #   false (default): deny login and log the error (secure default)
  #   true:            log a warning and allow login (availability-first)
  fail_open: false

  # event_store_path is the directory where received events are persisted.
  # Must be readable and writable by opksshuser.
  # Default: /var/lib/opk/caep-events
  event_store_path: /var/lib/opk/caep-events

  # blocking_events is the list of CAEP/RISC event type URIs that block login.
  # If omitted, all five default types above are used.
  blocking_events:
    - https://schemas.openid.net/secevent/caep/event-type/session-revoked
    - https://schemas.openid.net/secevent/risc/event-type/account-disabled
    - https://schemas.openid.net/secevent/risc/event-type/account-purged
    - https://schemas.openid.net/secevent/risc/event-type/account-compromised
    - https://schemas.openid.net/secevent/risc/event-type/credential-compromise

  # streams is a list of SSF stream configurations, one per OIDC provider.
  # Register each stream with the provider before adding it here.
  streams:
    - issuer: https://your-provider.example.com
      polling_endpoint: https://your-provider.example.com/ssf/events
      stream_token: <bearer-token-from-stream-registration>
      audience: https://your-ssh-server.example.com
```

### File permissions

`/etc/opk/config.yml` must have the same permissions as all other opkssh
server configuration files:

```bash
sudo chown root:opksshuser /etc/opk/config.yml
sudo chmod 640 /etc/opk/config.yml
```

### Event store directory

Create the event store directory and give ownership to `opksshuser`:

```bash
sudo mkdir -p /var/lib/opk/caep-events
sudo chown opksshuser:opksshuser /var/lib/opk/caep-events
sudo chmod 750 /var/lib/opk/caep-events
```

`opkssh verify` (running as `opksshuser`) both writes events from the SSF
poll and reads them for login evaluation. No root access is required.

---

## Provider setup guides

### Okta

Okta supports the full SSF specification including polling delivery (RFC 8936).

#### 1. Register an SSF stream

Use the Okta SSF Stream Management API to register a polling stream.
Authenticate with an Okta API token that has the required SSF stream
management scope (see
[Okta SSF configuration guide](https://developer.okta.com/docs/guides/configure-ssf-receiver/main/)
for the current scope name and authentication method).

For polling delivery (`urn:ietf:rfc:8936`), do **not** include an
`endpoint_url` in the request — that field is used for push delivery only.
The transmitter returns the polling endpoint URL in its response.

```bash
curl -X POST https://your-org.okta.com/api/v1/ssf/stream \
  -H "Authorization: Bearer <okta-api-token>" \
  -H "Content-Type: application/json" \
  -d '{
    "delivery": {
      "method": "urn:ietf:rfc:8936"
    },
    "events_requested": [
      "https://schemas.openid.net/secevent/caep/event-type/session-revoked",
      "https://schemas.openid.net/secevent/risc/event-type/account-disabled",
      "https://schemas.openid.net/secevent/risc/event-type/account-compromised"
    ]
  }'
```

The response includes:
- `stream_id` — record this for reference
- `delivery.endpoint_url` — the polling endpoint URL opkssh will call
- A stream bearer token (obtain via Okta's stream token endpoint or from the
  registration response; consult the Okta SSF guide above for exact steps)

#### 2. Add the stream to `/etc/opk/config.yml`

```yaml
cae:
  enabled: true
  streams:
    - issuer: https://your-org.okta.com
      polling_endpoint: https://your-org.okta.com/api/v1/ssf/stream/poll
      stream_token: <bearer-token>
      audience: https://your-ssh-server.example.com
```

#### 3. Verify

Trigger a session revocation in Okta for a test user.
On their next SSH login attempt, `/var/log/opkssh.log` should contain:

```
CAE: stored event type="https://schemas.openid.net/secevent/caep/event-type/session-revoked" iss="https://your-org.okta.com" sub="<user-subject>"
failed to verify: access denied by CAE evaluation: CAE: login denied due to security event "https://schemas.openid.net/secevent/caep/event-type/session-revoked" received at <RFC3339-timestamp>
```

---

### Microsoft Azure / Entra ID

> [!IMPORTANT]
> Azure's SSF transmitter for external receivers is in preview as of 2025.
> Check [Microsoft's documentation](https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-continuous-access-evaluation)
> for current availability. The app registration steps below are required
> regardless and prepare your app for CAE support now and once the SSF
> transmitter becomes generally available.

Azure Entra ID implements CAE through the **CP1 client capability**.
Applications that declare CP1 support:

- Receive **long-lived access tokens** (up to 28 hours, vs. the default
  1 hour) that Entra ID can revoke early via CAEP.
- Signal to Entra that they are capable of handling revocation events.
- Are eligible to receive CAEP events via the SSF transmitter once it
  is generally available.

Without CP1, tokens expire on their own schedule and Entra will not
send early-revocation signals to your app.

#### 1. Declare CP1 capability in the App Registration

In the [Azure portal](https://portal.azure.com/):

1. Open **Entra ID** → **App registrations** → your opkssh app.
2. Click **Manifest** in the left menu.
3. Locate the `optionalClaims` section and add the `xms_cc` claim to
   **access tokens**:

```json
"optionalClaims": {
    "accessToken": [
        {
            "name": "xms_cc",
            "additionalProperties": ["cp1"]
        }
    ],
    "idToken": [],
    "saml2Token": []
}
```

4. Click **Save**.

Alternatively, navigate to **Token configuration** → **Add optional claim**
→ select **Access token** → choose `xms_cc`, then add `cp1` as an additional
property.

> [!NOTE]
> The `xms_cc` claim with value `cp1` in the access token is what tells
> Entra this is a CAE-enabled application. Entra will only issue long-lived
> CAE tokens to apps that carry this claim.

#### 2. (Optional) Embed the access token for userinfo claims

> [!NOTE]
> This step is independent of CAE and SSF polling. The SSF stream is
> authenticated with the static `stream_token` admin credential configured in
> `/etc/opk/config.yml`, not with the per-user access token.

If your policy depends on claims that Entra ID only exposes through the
userinfo endpoint, set `send_access_token: true` for the Azure provider in
`~/.opk/config.yml`:

```yaml
providers:
  - alias: azure microsoft
    issuer: https://login.microsoftonline.com/{TENANT_ID}/v2.0
    client_id: {CLIENT_ID}
    scopes: openid profile email offline_access
    access_type: offline
    prompt: consent
    redirect_uris:
      - http://localhost:3000/login-callback
      - http://localhost:10001/login-callback
      - http://localhost:11110/login-callback
    send_access_token: true
```

See [Relationship to `send_access_token`](#relationship-to-send_access_token)
below for details.

#### 3. Configure the SSF stream (once Azure SSF transmitter is available)

Once Microsoft publishes the Azure SSF transmitter endpoint, register a
polling stream and add it to `/etc/opk/config.yml`:

```yaml
cae:
  enabled: true
  streams:
    - issuer: https://login.microsoftonline.com/{TENANT_ID}/v2.0
      polling_endpoint: https://graph.microsoft.com/beta/security/continuousAccessEvaluationPolicy/events  # placeholder — verify with Microsoft docs
      stream_token: <bearer-token>
      audience: https://your-ssh-server.example.com
```

> [!NOTE]
> Monitor [Microsoft's CAE documentation](https://learn.microsoft.com/en-us/entra/identity-platform/app-resilience-continuous-access-evaluation)
> for the exact SSF transmitter endpoint and registration procedure.

---

### Google

> [!NOTE]
> Google supports RISC events for **consumer accounts** (gmail.com)
> but not for Google Workspace accounts. Delivery is **push-only**
> (Google POSTs events to a receiver URL). Google does not currently support
> the SSF polling model (RFC 8936) that opkssh uses.
>
> When Google adds polling support, no changes to opkssh will be required —
> register the stream and add it to the `cae.streams` list.

Google's RISC endpoint and event schema are documented at
[developers.google.com/identity/protocols/risc](https://developers.google.com/identity/protocols/risc).

---

### GitLab and GitHub

Neither GitLab nor GitHub Actions (`https://token.actions.githubusercontent.com`)
currently publish an SSF transmitter endpoint. CAE evaluation is not
available for these providers.

---

## Relationship to `send_access_token`

CAE via SSF polling operates entirely server-side and does **not** require
the SSH certificate to contain an access token. The SSF stream bearer token
(`stream_token` in config) is what authenticates polling requests, not the
per-user access token.

`send_access_token: true` is a separate feature that allows the server to
call the provider's userinfo endpoint for additional claims. It is useful
alongside CAE but is not a prerequisite.

---

## Troubleshooting

### Login is denied unexpectedly

Check the opkssh log at `/var/log/opkssh.log`:

```
# Written by the poller when an event is received (one line per event type):
CAE: stored event type="<event-type-uri>" iss="<issuer>" sub="<subject>"

# Written at login denial:
failed to verify: access denied by CAE evaluation: CAE: login denied due to security event "<event-type-uri>" received at <RFC3339-timestamp>
```

If the event was stored from a previous session that has since been
re-authenticated, the user should re-run `opkssh login`. A new PK token
with a later `iat` will not be blocked by events received before it was
issued.

### CAE check passes even though the session was revoked

Possible causes:

1. **No SSF stream configured** for the user's issuer — check that the
   `issuer` field in `cae.streams` exactly matches the `iss` claim in the
   user's token (run `opkssh inspect ~/.ssh/id_ecdsa-cert.pub`).
2. **Polling endpoint unreachable** — if `fail_open: true` is set, poll
   errors produce a log warning but allow the login. Check the log.
3. **Provider does not support SSF polling** — see the provider support
   table above.

### `failed to create event store directory`

The event store directory does not exist or `opksshuser` lacks write
permission. Run:

```bash
sudo mkdir -p /var/lib/opk/caep-events
sudo chown opksshuser:opksshuser /var/lib/opk/caep-events
sudo chmod 750 /var/lib/opk/caep-events
```

### `SSF poll endpoint returned HTTP 401`

The `stream_token` has expired or is incorrect. Re-register the SSF stream
with the provider to obtain a fresh token and update `/etc/opk/config.yml`.

## See Also

- [opkssh configuration files](config.md)
- [Policy plugins](policyplugins.md)
- [Azure provider setup](providers/azure.md)
- [OpenID Shared Signals Framework specification](https://openid.net/specs/openid-sharedsignals-framework-1_0-final.html)
- [OpenID CAEP specification](https://openid.net/specs/openid-caep-1_0-final.html)
- [OpenID RISC specification](https://openid.net/specs/openid-risc-1_0-final.html)
- [RFC 8936: Poll-Based SET Delivery](https://www.rfc-editor.org/rfc/rfc8936.html)
