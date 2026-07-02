# Scenario YAML Schema Draft

## Purpose

This document defines the first author-facing YAML scenario format for the synthetic log generator. The format is
designed for the `linux-mini-lab` environment, the source-neutral event taxonomy, and the two canonical MVP scenarios.

The schema should let authors describe meaningful activity without embedding Zeek, Apache, auditd, firewall, or
SIEM-specific fields. Source-specific records are derived later from source-neutral events, the environment template,
and generator configuration.

## Design Goals

- Keep common scenarios readable without requiring Python code.
- Map every authored event to one or more source-neutral events with deterministic IDs and timestamps.
- Keep environment references explicit enough to validate before generation.
- Support absolute timestamps, offsets from scenario start, and dependency-based offsets.
- Allow optional ATT&CK and answer-key metadata without making it part of every event.
- Leave space for later noise profiles while keeping MVP scenarios deterministic and quiet by default.

## Non-Goals

- YAML should not expose source-native fields such as Zeek `uid`, Apache byte counts, auditd serial numbers, or native
  timestamp strings.
- YAML should not become a general programming language.
- YAML should not model SIEM routing, parser configuration, index names, dashboards, or pipeline settings.
- YAML should not require authors to write helper DNS or connection events for normal web requests unless the scenario
  specifically needs low-level control.

## File Shape

A scenario file contains one scenario document. Multi-scenario files are deferred until there is a concrete need for
batch authoring.

```yaml
schema_version: scenario/v0.1
id: scenario-example
name: Example Scenario
description: Short human-readable purpose.
seed: 1001
environment:
  id: linux-mini-lab
  version: "0.1"
time_range:
  start: 2026-01-15T14:00:00Z
  end: 2026-01-15T14:05:00Z
output_families:
  - generic-normalized
events: []
attack_chain: []
answer_key: []
metadata: {}
```

## Top-Level Fields

| Field | Required | Type | Description |
| --- | --- | --- | --- |
| `schema_version` | yes | string | Scenario schema version. MVP value is `scenario/v0.1`. |
| `id` | yes | string | Stable, filesystem-safe scenario ID. |
| `name` | yes | string | Human-readable scenario name. |
| `description` | no | string | Short scenario purpose or analyst-facing summary. |
| `seed` | yes | integer | Deterministic seed for helper event IDs, timestamps, and future plugin-owned values. |
| `environment` | yes | object or string | Environment template reference. String shorthand maps to `environment.id`. |
| `time_range` | yes | object | Scenario start and optional end timestamps. |
| `output_families` | no | list[string] | Requested output families. Defaults to `generic-normalized`. |
| `events` | yes | list[object] | Authored source-neutral activity events. |
| `attack_chain` | no | list[object] | Optional high-level attack sequence metadata. |
| `answer_key` | no | list[object] | Optional hidden labels and supporting event references. |
| `metadata` | no | object | Source-neutral scenario-level labels and notes. |

### `environment`

The long form is preferred when a version is known:

```yaml
environment:
  id: linux-mini-lab
  version: "0.1"
```

The short form is accepted for local sketches and maps to the current supported version:

```yaml
environment: linux-mini-lab
```

Validation should warn when the short form depends on an implicit version. It should fail when the environment ID is
unknown.

### `time_range`

```yaml
time_range:
  start: 2026-01-15T14:00:00Z
  end: 2026-01-15T14:05:00Z
```

`start` is required and defines the base for relative `at` values. `end` is optional in MVP authoring, but it is useful
for validating that generated helper events remain inside the intended scenario window.

### `output_families`

`output_families` names requested output groups, not source-specific event fields. The MVP default is:

```yaml
output_families:
  - generic-normalized
```

`generic-normalized` is always available because it is emitted from expanded source-neutral events. Source-specific
families such as `zeek`, `apache`, `auditd`, and `firewall` are generated only when all of these are true:

- The scenario requests the family in `output_families`.
- The environment has a host, sensor, or network device with a matching `logging_profiles` family.
- The event type, target service, and visibility rules support that family.

For example, requesting `apache` does not create Apache output for every web request. The request must target a service
hosted by an environment host with an Apache-capable logging profile, such as `svc-web-http` on `web-server-01`.
Requesting `zeek` requires a sensor profile and visibility into the relevant traffic path.
Requesting `firewall` requires a network device on the computed path with a logged matching policy rule.

## Event Shape

Each item under `events` is an authored event. It uses concise author-facing field names that map to the taxonomy's
source-neutral model.

```yaml
events:
  - id: evt-example-web-001
    type: web_request
    at: +2s
    actor: user-alice
    source_host: linux-ws-01
    service: svc-web-http
    method: GET
    path: /
    status: success
    correlation_id: corr-example-001
```

### Common Event Fields

| Field | Required | Type | Description |
| --- | --- | --- | --- |
| `id` | no | string | Stable authored event ID. Required for canonical MVP fixtures. |
| `type` | yes | string | Source-neutral event type, such as `web_request`. |
| `at` | conditional | timestamp or offset | Absolute timestamp or offset from scenario start. |
| `after` | conditional | string | Event ID that this event depends on. |
| `delay` | conditional | duration | Offset from the referenced `after` event. Defaults to `0s` when `after` is present. |
| `actor` | event-specific | string | User ID or username. User IDs are preferred. |
| `source_host` | event-specific | string | Origin host ID, hostname, FQDN, or IP address. Host IDs are preferred. |
| `target_host` | event-specific | string | Host receiving local activity, such as a Linux login. |
| `service` | event-specific | string | Service ID. Preferred for modeled internal services. |
| `status` | no | string | One of `success`, `failure`, `denied`, or `unknown`. Defaults are event-specific. |
| `correlation_id` | no | string | Group ID for related activity. Generated when omitted. |
| `metadata` | no | object | Source-neutral labels and scenario context. |
| `attack` | no | object | Optional ATT&CK-style context. |

An event must include either `at` or `after`. If both are present, `at` is authoritative and `after` is used only for
lineage. Authors should avoid that combination unless they need explicit parentage with an absolute timestamp.

## Timestamp Syntax

### Absolute Timestamps

Absolute timestamps must be timezone-aware ISO 8601 strings. UTC `Z` notation is preferred.

```yaml
at: 2026-01-15T14:00:02Z
```

Naive timestamps without a timezone should be rejected. Local time conversion is out of scope for the MVP.

### Relative Offsets

Relative offsets use a leading `+` from `time_range.start`.

```yaml
at: +18s
```

Supported MVP units:

| Unit | Meaning |
| --- | --- |
| `ms` | milliseconds |
| `s` | seconds |
| `m` | minutes |
| `h` | hours |

Compound durations such as `1m30s` may be accepted later, but MVP examples should use a single unit for simple
parsing and clearer validation messages.

### Dependency-Based Timing

`after` references a previous authored event ID. `delay` is measured from that referenced event's authored timestamp.

```yaml
after: evt-misuse-web-001
delay: 18s
```

The referenced event must appear earlier in the authored event list. This keeps ordering deterministic and avoids
cycle detection complexity in the first parser.

## Event Type Fields

### `web_request`

```yaml
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

Required fields:

| Field | Description |
| --- | --- |
| `actor` | User responsible for the request. |
| `source_host` | Client host making the request. |
| `service` | Target web service. |
| `method` | HTTP method. |
| `path` | Request path without scheme or host. |

Optional fields:

| Field | Description |
| --- | --- |
| `status_code` | Overrides the service route default. |
| `query_string` | Query string without the leading `?`. |
| `headers` | Source-neutral request header hints. |
| `metadata` | Labels such as download classification overrides. |
| `attack` | Optional ATT&CK-style context. |

Expansion should generate helper `dns_lookup` and `network_connection` events by default when the target service is an
internal modeled service and no compatible helper events already exist in the same correlation.

### `linux_local_login`

```yaml
- id: evt-misuse-web-001
  type: linux_local_login
  at: +0s
  actor: user-alice
  target_host: linux-ws-01
  login_method: local_console
  metadata:
    activity_classification: suspicious
  correlation_id: corr-local-account-misuse-001
```

Required fields:

| Field | Description |
| --- | --- |
| `actor` | User attempting the login. |
| `target_host` | Host receiving the login attempt. |
| `login_method` | Login mechanism, such as `local_console`. |

Optional fields:

| Field | Description |
| --- | --- |
| `source_host` | Remote origin host when the login is not local console activity. |
| `source_ip` | Remote origin IP when available. |
| `metadata` | Scenario labels, such as `activity_classification`. |

### Manual Helper Events

Authors may explicitly create `dns_lookup` or `network_connection` events when the default expansion is not precise
enough. This should be reserved for scenarios that need unusual failure behavior, direct IP traffic, specific timing,
or validation tests.

```yaml
- id: evt-manual-dns-001
  type: dns_lookup
  at: +0s
  actor: user-alice
  source_host: linux-ws-01
  service: svc-dns
  query_name: web-server-01.internal
  query_type: A
  status: success
```

Manual helper events must use the same source-neutral fields documented in the event taxonomy.

## Correlation and Parentage

`correlation_id` groups related events across source-neutral event types and future generated records. If omitted, the
parser should derive one deterministic correlation ID for each top-level activity chain.

Parentage is derived from `after` and helper expansion:

- A manually authored event with `after` should use the referenced event as its parent unless the event type's
  expansion creates a more specific immediate parent.
- A generated `network_connection` helper should be a child of the generated or authored `dns_lookup`.
- A generated `web_request` expanded event should be a child of the generated or authored `network_connection`.
- In login-driven activity, the first helper event after the login should be a child of the login.

When an authored `web_request` expands into helper events, the authored event ID belongs to the final `web_request`
source-neutral event. Helper event IDs are generated deterministically unless the scenario later supports explicit
helper ID overrides.

## Attack Chain

`attack_chain` describes scenario-level attack progression for training and answer keys. It does not replace event
fields and should not be required for benign scenarios.

```yaml
attack_chain:
  - id: step-download
    name: Archive download
    primary_event_id: evt-misuse-web-005
    technique_id: T1105
    technique_name: Ingress Tool Transfer
```

MVP fields:

| Field | Required | Description |
| --- | --- | --- |
| `id` | yes | Stable step ID. |
| `name` | yes | Human-readable step name. |
| `primary_event_id` | yes | Event that best represents the step. |
| `supporting_event_ids` | no | Related event IDs. |
| `technique_id` | no | ATT&CK technique ID. |
| `technique_name` | no | ATT&CK technique name. |

## Answer Key

`answer_key` contains hidden ground-truth labels that should be written only to metadata outputs, not generated logs.

```yaml
answer_key:
  - label: suspicious_internal_web_download
    primary_event_id: evt-misuse-web-005
    supporting_event_ids:
      - evt-misuse-web-001
      - evt-misuse-web-004
    description: Suspicious local account use followed by admin page access and archive download.
```

Validation should fail when answer-key event references do not resolve to authored or expanded event IDs.

## Canonical Scenario Examples

### Benign Internal Web Browsing

```yaml
schema_version: scenario/v0.1
id: scenario-benign-internal-web
name: Benign Internal Web Browsing
description: Alice visits the internal Apache homepage from her normal workstation.
seed: 1001
environment:
  id: linux-mini-lab
  version: "0.1"
time_range:
  start: 2026-01-15T14:00:00Z
  end: 2026-01-15T14:00:10Z
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

Expected expansion:

| Event ID | Type | Timestamp | Parent |
| --- | --- | --- | --- |
| generated helper | `dns_lookup` | `2026-01-15T14:00:00Z` | none |
| generated helper | `network_connection` | `2026-01-15T14:00:01Z` | DNS helper |
| `evt-benign-web-003` | `web_request` | `2026-01-15T14:00:02Z` | connection helper |

The canonical expanded scenario uses fixed helper IDs in `docs/canonical-scenarios.md`. The YAML parser can either
derive those exact IDs from a deterministic helper ID rule or allow a future helper override mechanism before Phase 1
fixtures are finalized.

### Local Account Misuse and Suspicious Web Access

```yaml
schema_version: scenario/v0.1
id: scenario-local-account-misuse-web
name: Local Account Misuse and Suspicious Web Access
description: Suspicious use of Alice's local account followed by admin browsing and archive download.
seed: 2002
environment:
  id: linux-mini-lab
  version: "0.1"
time_range:
  start: 2026-01-15T03:12:00Z
  end: 2026-01-15T03:13:00Z
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
attack_chain:
  - id: step-admin-access
    name: Admin page access
    primary_event_id: evt-misuse-web-004
    technique_id: T1087
    technique_name: Account Discovery
  - id: step-archive-download
    name: Archive download
    primary_event_id: evt-misuse-web-005
    supporting_event_ids:
      - evt-misuse-web-001
      - evt-misuse-web-004
    technique_id: T1105
    technique_name: Ingress Tool Transfer
answer_key:
  - label: suspicious_internal_web_download
    primary_event_id: evt-misuse-web-005
    supporting_event_ids:
      - evt-misuse-web-001
      - evt-misuse-web-004
    description: Suspicious local account use followed by admin page access and archive download.
```

Expected expansion:

| Event ID | Type | Timestamp | Parent |
| --- | --- | --- | --- |
| `evt-misuse-web-001` | `linux_local_login` | `2026-01-15T03:12:00Z` | none |
| generated helper | `dns_lookup` | `2026-01-15T03:12:15Z` | `evt-misuse-web-001` |
| generated helper | `network_connection` | `2026-01-15T03:12:16Z` | DNS helper |
| `evt-misuse-web-004` | `web_request` | `2026-01-15T03:12:18Z` | connection helper |
| `evt-misuse-web-005` | `web_request` | `2026-01-15T03:12:28Z` | connection helper |

The second web request should reuse the compatible connection generated for the first web request because both events
share source host, service, actor, and correlation ID.

## Validation Behavior

Validation should happen before output writing. Errors should include the scenario ID, field path, invalid value, and
actionable reason.

### Structural Validation

- Required top-level fields must exist.
- `schema_version` must be supported.
- `id`, event IDs, correlation IDs, and labels must be filesystem-safe identifiers.
- `events` must be non-empty for MVP scenarios.
- Event IDs must be unique within a scenario.
- Every event must include `at` or `after`.
- `after` references must point to an earlier event in the same `events` list.
- `delay` may appear only with `after`.
- `time_range.start` and absolute event timestamps must be timezone-aware.

### Environment Reference Validation

- `environment.id` must resolve to a known template.
- `environment.version` must be supported when provided.
- `actor` must resolve to a known user.
- `source_host` and `target_host` must resolve to known hosts.
- `service` must resolve to a known service.
- Successful `linux_local_login` events must target a host listed in the user's `login_hosts`.
- Successful `web_request` events must target a service with HTTP protocol.
- `web_request.method` and `web_request.path` should match a known route unless the event intentionally models an
  unknown route or status override.

### Field Validation

- Unknown top-level fields should produce warnings in early drafts and errors once the schema stabilizes.
- Unknown event fields should be errors by default because typos can silently change generated activity.
- `status` must be one of `success`, `failure`, `denied`, or `unknown`.
- `status_code` must be an integer between 100 and 599.
- `path` must start with `/`.
- `attack.technique_id` should match the simple pattern `T` followed by digits, with optional sub-technique suffixes
  deferred until needed.
- `metadata` values should be strings, numbers, booleans, arrays, or nested objects that can serialize to JSON.

### Expansion Validation

- Generated helper events must stay inside `time_range` when `end` is provided.
- Generated helper timestamps must not sort after their dependent authored event.
- A generated DNS lookup for a known internal service must resolve through environment DNS records.
- A generated network connection must use the service target host, IP address, port, and protocol.
- Sensor visibility should be checked before future source-specific Zeek records are expected.
- Firewall policy should be checked before future source-specific firewall records are expected.
- Download classification should be derived from `web_request.path` and should not require a separate event type.

## Error Message Expectations

Error messages should be specific enough for authors to fix the YAML without reading parser code.

| Mistake | Example Message |
| --- | --- |
| Unknown user | `scenario-benign-internal-web events[0].actor: unknown user 'user-aliice'` |
| Unknown host | `scenario-benign-internal-web events[0].source_host: unknown host 'linux-ws-99'` |
| Unknown service | `scenario-benign-internal-web events[0].service: unknown service 'svc-web-https'` |
| Invalid login host | `scenario-local-account-misuse-web events[0].target_host: user 'user-alice' cannot log in to 'linux-ws-02'` |
| Missing timestamp | `scenario-example events[0]: expected either 'at' or 'after'` |
| Bad dependency | `scenario-example events[2].after: event 'evt-missing' is not defined before this event` |
| Unknown field | `scenario-example events[0].user: unknown field; use 'actor' for user references` |
| Bad route | `scenario-example events[0].path: route 'POST /admin/archive.tar.gz' is not defined for service 'svc-web-http'` |

## YAML Versus Python Authoring

YAML is appropriate when:

- The scenario is deterministic and mostly linear.
- Events can be written as a short list of meaningful actions.
- Helper DNS and connection behavior can use default expansion.
- Validation should reject impossible environment references early.
- The author wants a reviewable fixture for tests or documentation.

Python authoring should be recommended when:

- The scenario needs loops, branching, or calculated event counts.
- Event timing depends on generated data or probabilistic distributions.
- Noise generation is significant enough to require reusable helper functions.
- The scenario needs custom expansion logic that would make YAML hard to read.
- The author is creating a library of related scenarios with shared setup code.

## Noise Profiles

Noise is intentionally absent from the MVP canonical scenarios. The schema leaves room for a future top-level
`noise_profiles` field:

```yaml
noise_profiles:
  - id: light-business-hours-web
    actor_pool:
      - user-bob
      - user-carol
```

Until noise behavior is implemented, validators should reject `noise_profiles` with an explicit "not supported yet"
message instead of silently ignoring it.

## Phase 2 Handoff

YAML loading is deferred until Phase 2 so Phase 1 can prove the source-neutral core model first. When YAML
implementation starts, it can begin with this subset:

- Parse one YAML document per file.
- Support `schema_version`, `id`, `name`, `seed`, `environment`, `time_range`, `output_families`, `events`,
  `attack_chain`, and `answer_key`.
- Support `web_request` and `linux_local_login` as authored event types.
- Expand `web_request` into DNS and network helpers for `svc-web-http`.
- Validate all environment references against `linux-mini-lab`.
- Generate source-neutral events only; source-specific records remain deferred.
- Keep helper ID generation deterministic enough for exact test assertions.

## Decisions Incorporated

- YAML authors describe user-visible activity; helper DNS and network events can be generated.
- `service` is the preferred authoring reference for internal service traffic.
- `output_families` describes requested output families and does not inject source-native event fields.
- ATT&CK fields remain optional and nested under `attack`.
- Answer-key labels are metadata outputs, never generated log records.
- Download behavior is inferred from a `web_request` path instead of represented by a separate event.
