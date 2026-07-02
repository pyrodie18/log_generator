# Canonical Scenarios

## Purpose

This document defines the two deterministic MVP scenarios for the synthetic log generator. The scenarios are
source-neutral first: they describe modeled activity, event lineage, correlation behavior, validation expectations, and
future source-specific records without requiring Phase 1 to generate Zeek, Apache, auditd, or firewall logs.

Both scenarios use the `linux-mini-lab` environment template and must reference only entities defined there.

## Common Scenario Rules

### Environment

| Field | Value |
| --- | --- |
| Environment ID | `linux-mini-lab` |
| Environment Version | `0.1` |
| Time Zone | UTC |

All authored timestamps are timezone-aware UTC timestamps. Relative offsets are measured from each scenario's
`start_time`.

### Deterministic Identifiers

Scenario authors should be able to provide stable IDs directly. When IDs are omitted later, implementation code may
derive them from the scenario seed, scenario ID, event type, and event sequence index.

| Identifier Type | MVP Rule |
| --- | --- |
| Scenario ID | Human-authored, filesystem-safe, and stable across runs. |
| Event ID | Human-authored in these canonical scenarios for exact test assertions. |
| Correlation ID | Shared across events that describe one user-visible activity chain. |
| Parent Event ID | Points to the immediate causal parent when the relationship is useful for lineage. |
| Seed | Fixed per scenario to keep generated timestamps, record IDs, and future plugin-owned values reproducible. |

Event IDs identify individual source-neutral events. Correlation IDs group related events that may later emit records
from different log sources. A single correlation ID can span DNS, connection, HTTP, web-server, and answer-key
metadata.

### Common Event Envelope

Each canonical event should eventually map to a common envelope with at least these fields:

| Field | Requirement |
| --- | --- |
| `event_id` | Required stable event identifier. |
| `scenario_id` | Required scenario identifier. |
| `event_type` | Required normalized event type. |
| `timestamp` | Required UTC timestamp. |
| `actor_user_id` | Optional when the activity is user-driven. |
| `source_host_id` | Required for host-originated activity. |
| `service_id` | Required when activity targets a modeled service. |
| `destination_host_id` | Derived from `service_id` for authored events when possible. |
| `status` | Required status using `success`, `failure`, `denied`, or `unknown`. |
| `correlation_id` | Required for these scenarios. |
| `parent_event_id` | Optional lineage pointer. |
| `metadata` | Optional source-neutral scenario context. |

Future taxonomy work may add fields or rename the envelope, but these scenarios rely on this conceptual shape.

### Future Record Ownership

Source-specific records are listed to guide later generators. Phase 1 should produce only source-neutral events and
generic normalized JSON Lines unless a later phase expands the implementation boundary.

| Source | Owning Environment Entity | Future Streams |
| --- | --- | --- |
| Zeek | `zeek-sensor-01` | `dns.log`, `conn.log`, `http.log` |
| Apache | `web-server-01` | `access.log` |
| auditd | `linux-ws-01` | `audit.log` |
| Firewall | `boundary-fw-01` | `traffic.log` |
| Ground truth | Scenario writer | `metadata/ground-truth.jsonl` |

Plugin-owned values such as Zeek `uid`, Apache byte counts, user agents, audit record serial numbers, and exact
source-specific timestamp formats should not be stored as required source-neutral event fields.

### Web Request Download Classification

Scenario authors should model an HTTP transaction as one `web_request`. A generator should classify the request as a
download when the path points to a file that is not an HTML page. Paths ending in `/`, paths with no file extension,
and paths ending in `.html` or `.htm` are page or directory requests rather than downloads.

## Scenario `scenario-benign-internal-web`

### Summary

| Field | Value |
| --- | --- |
| Display Name | Benign Internal Web Browsing |
| Purpose | Model a normal user visiting the internal Apache homepage. |
| Seed | `1001` |
| Start Time | `2026-01-15T14:00:00Z` |
| Actor | `user-alice` (`alice`) |
| Source Host | `linux-ws-01` (`10.10.10.11`) |
| DNS Resolver | `lab-dns-01` (`10.10.20.53`) |
| Destination Service | `svc-web-http` on `web-server-01` (`10.10.20.21:80`) |
| Correlation ID | `corr-benign-internal-web-001` |
| Expected Event Count | 3 |

Alice uses her normal workstation to resolve `web-server-01.internal`, opens an HTTP connection, and requests the
homepage at `/`. The activity is benign and should not produce answer-key suspicion records.

### Event Sequence

| Offset | Event ID | Type | Status | Parent | Description |
| --- | --- | --- | --- | --- | --- |
| `+0s` | `evt-benign-web-001` | `dns_lookup` | `success` | none | Resolve `web-server-01.internal`. |
| `+1s` | `evt-benign-web-002` | `network_connection` | `success` | `evt-benign-web-001` | Open HTTP connection. |
| `+2s` | `evt-benign-web-003` | `web_request` | `success` | `evt-benign-web-002` | Request `GET /`. |

The scenario author only models the `web_request`. Later generators should inspect `svc-web-http`, identify that the
service is backed by Apache, and emit the correct Apache access record as generated output.

### Event Details

#### `evt-benign-web-001`

| Field | Value |
| --- | --- |
| `event_type` | `dns_lookup` |
| `timestamp` | `2026-01-15T14:00:00Z` |
| `actor_user_id` | `user-alice` |
| `source_host_id` | `linux-ws-01` |
| `destination_host_id` | `lab-dns-01` |
| `service_id` | `svc-dns` |
| `query_name` | `web-server-01.internal` |
| `query_type` | `A` |
| `resolved_addresses` | `10.10.20.21` |
| `status` | `success` |
| `correlation_id` | `corr-benign-internal-web-001` |

#### `evt-benign-web-002`

| Field | Value |
| --- | --- |
| `event_type` | `network_connection` |
| `timestamp` | `2026-01-15T14:00:01Z` |
| `actor_user_id` | `user-alice` |
| `source_host_id` | `linux-ws-01` |
| `source_ip` | `10.10.10.11` |
| `destination_host_id` | `web-server-01` |
| `destination_ip` | `10.10.20.21` |
| `service_id` | `svc-web-http` |
| `destination_port` | `80` |
| `network_protocol` | `tcp` |
| `application_protocol` | `http` |
| `status` | `success` |
| `correlation_id` | `corr-benign-internal-web-001` |
| `parent_event_id` | `evt-benign-web-001` |

#### `evt-benign-web-003`

| Field | Value |
| --- | --- |
| `event_type` | `web_request` |
| `timestamp` | `2026-01-15T14:00:02Z` |
| `actor_user_id` | `user-alice` |
| `source_host_id` | `linux-ws-01` |
| `destination_host_id` | `web-server-01` |
| `service_id` | `svc-web-http` |
| `method` | `GET` |
| `url` | `http://web-server-01.internal/` |
| `path` | `/` |
| `status_code` | `200` |
| `status` | `success` |
| `correlation_id` | `corr-benign-internal-web-001` |
| `parent_event_id` | `evt-benign-web-002` |

### Future Source-Specific Records

| Event ID | Future Records | Notes |
| --- | --- | --- |
| `evt-benign-web-001` | Zeek `conn.log`, Zeek `dns.log`, firewall `traffic.log` | Visible to `zeek-sensor-01`; resolver traffic crosses `boundary-fw-01`. |
| `evt-benign-web-002` | Zeek `conn.log`, firewall `traffic.log` | Visible workstation-to-server traffic crosses `boundary-fw-01`. |
| `evt-benign-web-003` | Zeek `http.log`, Apache `access.log` | Network and server records derive from the request. |

### Validation Expectations

- `user-alice` must exist and must be valid on `linux-ws-01`.
- `linux-ws-01`, `lab-dns-01`, `web-server-01`, and `zeek-sensor-01` must resolve through the environment.
- `boundary-fw-01` must have allow rules for workstation-to-server DNS and HTTP traffic.
- `web-server-01.internal` must resolve to `10.10.20.21`.
- `svc-web-http` must target `web-server-01` on TCP port `80`.
- `GET /` must be a known route for `svc-web-http` with default status `200`.
- `zeek-sensor-01` must have visibility into workstation-to-server and server-to-workstation traffic.
- No ground-truth suspicion record should be generated for this scenario.

## Scenario `scenario-local-account-misuse-web`

### Summary

| Field | Value |
| --- | --- |
| Display Name | Local Account Misuse and Suspicious Web Access |
| Purpose | Model suspicious use of Alice's local account followed by internal admin browsing and archive download. |
| Seed | `2002` |
| Start Time | `2026-01-15T03:12:00Z` |
| Actor | `user-alice` (`alice`) |
| Source Host | `linux-ws-01` (`10.10.10.11`) |
| DNS Resolver | `lab-dns-01` (`10.10.20.53`) |
| Destination Service | `svc-web-http` on `web-server-01` (`10.10.20.21:80`) |
| Correlation ID | `corr-local-account-misuse-001` |
| Expected Event Count | 5 |

The scenario models attacker-controlled or suspicious use of Alice's local account on her valid workstation. The login
is valid according to environment account placement, but the scenario marks it suspicious because it occurs outside the
benign scenario context and is followed by administrative web access and a sensitive archive download.

### Event Sequence

| Offset | Event ID | Type | Status | Parent | Description |
| --- | --- | --- | --- | --- | --- |
| `+0s` | `evt-misuse-web-001` | `linux_local_login` | `success` | none | Alice logs in locally to `linux-ws-01`. |
| `+15s` | `evt-misuse-web-002` | `dns_lookup` | `success` | `evt-misuse-web-001` | Resolve `web-server-01.internal`. |
| `+16s` | `evt-misuse-web-003` | `network_connection` | `success` | `evt-misuse-web-002` | Open HTTP connection. |
| `+18s` | `evt-misuse-web-004` | `web_request` | `success` | `evt-misuse-web-003` | Request `GET /admin`. |
| `+28s` | `evt-misuse-web-005` | `web_request` | `success` | `evt-misuse-web-003` | Request archive path. |

The second web request reuses the existing network connection as its parent because it is part of the same browser
session. The `/admin/archive.tar.gz` path is classified as a download because it points to a non-HTML file.

### Event Details

#### `evt-misuse-web-001`

| Field | Value |
| --- | --- |
| `event_type` | `linux_local_login` |
| `timestamp` | `2026-01-15T03:12:00Z` |
| `actor_user_id` | `user-alice` |
| `target_host_id` | `linux-ws-01` |
| `login_method` | `local_console` |
| `status` | `success` |
| `correlation_id` | `corr-local-account-misuse-001` |
| `metadata.activity_classification` | `suspicious` |

#### `evt-misuse-web-002`

| Field | Value |
| --- | --- |
| `event_type` | `dns_lookup` |
| `timestamp` | `2026-01-15T03:12:15Z` |
| `actor_user_id` | `user-alice` |
| `source_host_id` | `linux-ws-01` |
| `destination_host_id` | `lab-dns-01` |
| `service_id` | `svc-dns` |
| `query_name` | `web-server-01.internal` |
| `query_type` | `A` |
| `resolved_addresses` | `10.10.20.21` |
| `status` | `success` |
| `correlation_id` | `corr-local-account-misuse-001` |
| `parent_event_id` | `evt-misuse-web-001` |

#### `evt-misuse-web-003`

| Field | Value |
| --- | --- |
| `event_type` | `network_connection` |
| `timestamp` | `2026-01-15T03:12:16Z` |
| `actor_user_id` | `user-alice` |
| `source_host_id` | `linux-ws-01` |
| `source_ip` | `10.10.10.11` |
| `destination_host_id` | `web-server-01` |
| `destination_ip` | `10.10.20.21` |
| `service_id` | `svc-web-http` |
| `destination_port` | `80` |
| `network_protocol` | `tcp` |
| `application_protocol` | `http` |
| `status` | `success` |
| `correlation_id` | `corr-local-account-misuse-001` |
| `parent_event_id` | `evt-misuse-web-002` |

#### `evt-misuse-web-004`

| Field | Value |
| --- | --- |
| `event_type` | `web_request` |
| `timestamp` | `2026-01-15T03:12:18Z` |
| `actor_user_id` | `user-alice` |
| `source_host_id` | `linux-ws-01` |
| `destination_host_id` | `web-server-01` |
| `service_id` | `svc-web-http` |
| `method` | `GET` |
| `url` | `http://web-server-01.internal/admin` |
| `path` | `/admin` |
| `status_code` | `200` |
| `status` | `success` |
| `correlation_id` | `corr-local-account-misuse-001` |
| `parent_event_id` | `evt-misuse-web-003` |
| `attack.technique_id` | `T1087` |
| `attack.technique_name` | Account Discovery |

The ATT&CK fields are optional event metadata. They should help future answer-key and training content, but Phase 1
models should not require ATT&CK fields on every event.

#### `evt-misuse-web-005`

| Field | Value |
| --- | --- |
| `event_type` | `web_request` |
| `timestamp` | `2026-01-15T03:12:28Z` |
| `actor_user_id` | `user-alice` |
| `source_host_id` | `linux-ws-01` |
| `destination_host_id` | `web-server-01` |
| `service_id` | `svc-web-http` |
| `method` | `GET` |
| `url` | `http://web-server-01.internal/admin/archive.tar.gz` |
| `path` | `/admin/archive.tar.gz` |
| `status_code` | `200` |
| `status` | `success` |
| `correlation_id` | `corr-local-account-misuse-001` |
| `parent_event_id` | `evt-misuse-web-003` |
| `attack.technique_id` | `T1105` |
| `attack.technique_name` | Ingress Tool Transfer |
| `metadata.download_classification` | `download` |
| `metadata.file_name` | `archive.tar.gz` |

### Future Source-Specific Records

| Event ID | Future Records | Notes |
| --- | --- | --- |
| `evt-misuse-web-001` | auditd `audit.log` | Generated by `linux-ws-01` because it has `profile-auditd-only`. |
| `evt-misuse-web-002` | Zeek `conn.log`, Zeek `dns.log`, firewall `traffic.log` | Visible to `zeek-sensor-01`; resolver traffic crosses `boundary-fw-01`. |
| `evt-misuse-web-003` | Zeek `conn.log`, firewall `traffic.log` | Visible workstation-to-server traffic crosses `boundary-fw-01`. |
| `evt-misuse-web-004` | Zeek `http.log`, Apache `access.log` | Network and server records derive from the request. |
| `evt-misuse-web-005` | Zeek `http.log`, Apache `access.log`, ground truth | Classified as the download. |

### Validation Expectations

- `user-alice` must exist and must be valid on `linux-ws-01`.
- The login is valid environment activity but should carry scenario metadata marking it suspicious.
- `linux-ws-01` must have an auditd-capable logging profile for future authentication telemetry.
- `boundary-fw-01` must have allow rules for workstation-to-server DNS and HTTP traffic.
- `web-server-01.internal` must resolve to `10.10.20.21`.
- `svc-web-http` must target `web-server-01` on TCP port `80`.
- `GET /admin` and `GET /admin/archive.tar.gz` must be known routes for `svc-web-http` with default status `200`.
- `zeek-sensor-01` must have visibility into workstation-to-server and server-to-workstation traffic.
- `/admin/archive.tar.gz` must be classified as a download because it is a non-HTML file path.
- ATT&CK metadata must remain optional and nested under attack context.

### Ground-Truth Expectations

Ground-truth records should be emitted only under `metadata/ground-truth.jsonl`, not inside source-specific logs. The
minimum answer-key content for this scenario is:

| Field | Value |
| --- | --- |
| `scenario_id` | `scenario-local-account-misuse-web` |
| `correlation_id` | `corr-local-account-misuse-001` |
| `label` | `suspicious_internal_web_download` |
| `primary_event_id` | `evt-misuse-web-005` |
| `supporting_event_ids` | `evt-misuse-web-001`, `evt-misuse-web-004` |
| `description` | Suspicious local account use followed by admin page access and archive download. |

## YAML Translation Targets

The later YAML schema should be able to express both scenarios without source-specific fields. These examples show the
intended authoring shape, not a finalized schema. They show the high-level authored events. The expanded event
sequence above shows the DNS and connection helper events that implementation tests can assert.

### Benign Scenario Sketch

```yaml
schema_version: scenario/v0.1
id: scenario-benign-internal-web
name: Benign Internal Web Browsing
seed: 1001
environment:
  id: linux-mini-lab
  version: "0.1"
time_range:
  start: 2026-01-15T14:00:00Z
output_families:
  - generic-normalized
events:
  - id: evt-benign-web-003
    type: web_request
    at: +2s
    actor: user-alice
    source_host: linux-ws-01
    service: svc-web-http
    method: GET
    path: /
    correlation_id: corr-benign-internal-web-001
```

### Misuse Scenario Sketch

```yaml
schema_version: scenario/v0.1
id: scenario-local-account-misuse-web
name: Local Account Misuse and Suspicious Web Access
seed: 2002
environment:
  id: linux-mini-lab
  version: "0.1"
time_range:
  start: 2026-01-15T03:12:00Z
output_families:
  - generic-normalized
events:
  - id: evt-misuse-web-001
    type: linux_local_login
    at: +0s
    actor: user-alice
    target_host: linux-ws-01
    login_method: local_console
    metadata:
      activity_classification: suspicious
    correlation_id: corr-local-account-misuse-001
  - id: evt-misuse-web-004
    type: web_request
    after: evt-misuse-web-001
    delay: 18s
    actor: user-alice
    source_host: linux-ws-01
    service: svc-web-http
    method: GET
    path: /admin
    attack:
      technique_id: T1087
      technique_name: Account Discovery
    correlation_id: corr-local-account-misuse-001
  - id: evt-misuse-web-005
    type: web_request
    after: evt-misuse-web-004
    delay: 10s
    actor: user-alice
    source_host: linux-ws-01
    service: svc-web-http
    method: GET
    path: /admin/archive.tar.gz
    attack:
      technique_id: T1105
      technique_name: Ingress Tool Transfer
    correlation_id: corr-local-account-misuse-001
answer_key:
  - label: suspicious_internal_web_download
    primary_event_id: evt-misuse-web-005
    supporting_event_ids:
      - evt-misuse-web-001
      - evt-misuse-web-004
```

## Phase 1 Test Targets

These scenarios should become exact source-neutral test fixtures in Phase 1.

| Test Target | Expected Assertion |
| --- | --- |
| Environment references | Every user, host, service, DNS name, and route resolves through `linux-mini-lab`. |
| Benign event count | `scenario-benign-internal-web` expands to exactly 3 source-neutral events. |
| Misuse event count | `scenario-local-account-misuse-web` expands to exactly 5 source-neutral events. |
| Event ordering | Events sort by timestamp, then authored sequence order for same-timestamp events. |
| Correlation behavior | All events in each scenario share the scenario's expected correlation ID. |
| Parent linkage | Every `parent_event_id` resolves to an earlier event in the same scenario. |
| Source boundaries | Future source outputs are derivable from event and environment metadata. |
| Optional attack metadata | Misuse events may include ATT&CK metadata, but benign events are valid without it. |

## Decisions Incorporated

- Scenario authors specify `web_request`; they do not author `apache_request` events.
- Web-server generators inspect the target service and emit the matching record type, such as Apache or nginx.
- Download behavior is inferred from one `web_request` when the path points to a non-HTML file.
- Generic normalized JSONL is an official MVP output family.
- Same-timestamp dependencies continue to use `after` plus `delay: 0s` in YAML sketches.

## Open Decisions Carried Forward

No scenario-level open decisions remain in this artifact. Broader YAML loading and manifest classification decisions
are tracked in `docs/phase-0-planning.md`.
