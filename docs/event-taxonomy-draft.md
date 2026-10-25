# Event Taxonomy Draft

## Purpose

This document defines the first source-neutral event taxonomy for the synthetic log generator. It is grounded in the
`linux-mini-lab` environment and the two canonical scenarios, so Phase 1 can implement event models without guessing
which fields are core model data and which fields belong to later source-specific generators.

The four scenario-required event types below are implemented in `src/log_generator/core/events.py`.
YAML authors `web_request` and `linux_local_login`; Python also supports manual `dns_lookup` and
`network_connection` events. Zeek output is implemented for DNS and HTTP activity. TLS and process events and other
source-specific families remain design proposals.

The taxonomy is intentionally small. Scenario authors describe meaningful activity once, and generators derive
source-specific records from the event, the environment, and the target service.

## Scope

### Phase 1 Required Event Types

- `dns_lookup`
- `network_connection`
- `web_request`
- `linux_local_login`

These event types are enough to model both canonical scenarios.

### Reserved Event Types

- `tls_connection`
- `process_execution`

These event types are kept in the taxonomy draft because the Phase 0 plan named them as early source-neutral events.
They are not required by the two canonical scenarios and should not block Phase 1 if the first implementation remains
strictly scenario-driven.

### Explicit Non-Events

- `apache_request` is not authored as a source-neutral event.
- `file_download` is not authored as a separate source-neutral event.
- `firewall_traffic` is not authored as a source-neutral event.

Apache, nginx, or other web-server records are generated from `web_request` events by inspecting the target service.
Download behavior is inferred from a single `web_request` path.
Firewall records are generated from `network_connection` events by inspecting the computed network path, network device
policy, and requested output families.

## Authoring and Expansion Model

The taxonomy separates authored scenario input from expanded source-neutral events.

Authored input should describe the meaningful activity. For example, a normal web scenario can author one
`web_request` against `svc-web-http` instead of separately authoring DNS and connection setup.

Expansion can create helper events when the environment has enough information:

- A `web_request` to an internal service can expand into a DNS lookup, a network connection, and the web request.
- A `web_request` after an existing compatible connection can reuse that connection instead of creating another one.
- A local login can be the parent of the first helper event in a suspicious activity chain.
- Firewall telemetry can be derived from generated or authored `network_connection` events when the computed path
  crosses a logged firewall policy rule.

Python authors may create `dns_lookup` or `network_connection` events manually when the scenario needs precise
low-level behavior, unusual timing, failed helper activity, or a direct test of those event types. These are not
supported authored YAML event types.

### Helper Event Timing

When helper events are generated automatically, expansion should place them before the event that needs them. The
canonical default for a first HTTP request is:

- DNS lookup two seconds before the `web_request`.
- Network connection one second before the `web_request`.
- The `web_request` at the authored timestamp.

If the scenario already has a compatible connection in the same correlation, later `web_request` events may reuse it.
Python authors can override this default by explicitly authoring the helper events. For the first YAML web request
after a local login, DNS and connection helpers are placed three and two seconds before the request, respectively.

## Service and Host References

`service_id` is the preferred authoring reference when an event targets a known service. The environment maps each
service to its target host, port, protocol, names, and route behavior.

Expanded events should include derived host and address fields when they are known. This denormalizes the event on
purpose: normalized JSONL, tests, and future output writers should not have to repeat environment lookups for common
fields such as `destination_host_id`, `destination_ip`, and `destination_port`.

An event may use host and address fields without `service_id` when it models lower-level traffic, unknown services, or
future external destinations.

## Common Envelope

Every source-neutral event should carry a common envelope. Type-specific fields live beside the envelope fields, not in
source-specific nested payloads.

### Required Envelope Fields

| Field | Type | Description |
| --- | --- | --- |
| `event_id` | string | Stable event identifier unique within a generated run. |
| `scenario_id` | string | Scenario that authored or produced the event. |
| `event_type` | string | One of the supported source-neutral event types. |
| `timestamp` | datetime | Timezone-aware UTC event timestamp. |
| `status` | string | Normalized event outcome. |
| `correlation_id` | string | Stable group ID for related events. |

### Optional Envelope Fields

| Field | Type | Description |
| --- | --- | --- |
| `parent_event_id` | string | Immediate causal parent event. |
| `actor_user_id` | string | Environment user responsible for the activity. |
| `source_host_id` | string | Environment host where the activity originated. |
| `destination_host_id` | string | Environment host targeted by the activity. |
| `service_id` | string | Environment service targeted by the activity. |
| `metadata` | object | Source-neutral scenario context and labels. |
| `attack` | object | Optional ATT&CK-style context for training and answer keys. |

### Status Values

| Status | Meaning |
| --- | --- |
| `success` | The modeled activity completed successfully. |
| `failure` | The activity failed for a modeled technical reason. |
| `denied` | The activity was blocked by access control or policy. |
| `unknown` | The activity outcome is intentionally unknown or not modeled. |

Status values are source-neutral. Generators may map them into source-native values such as HTTP status codes, auditd
result fields, or Zeek connection states.

## Identity and Lineage Rules

### Event IDs

`event_id` identifies one source-neutral event. Canonical scenarios provide stable IDs directly so tests can assert
exact values. Future authoring flows may derive IDs from the scenario seed, event type, and event sequence index.

### Correlation IDs

`correlation_id` groups related activity across event types and future log sources. For example, one web browsing
correlation can include DNS, network connection, HTTP, web-server, and ground-truth records.

Correlation IDs are not unique event identifiers. Multiple events can and usually should share the same correlation ID.

### Parent Event IDs

`parent_event_id` points to the immediate source-neutral event that caused or enabled the current event. Parentage
should remain simple and local:

- A `network_connection` can be a child of the DNS lookup that resolved the destination.
- A `web_request` can be a child of the network connection used for the request.
- A login-triggered activity chain can make the first DNS lookup a child of the login event.

Generated source-specific records should reference the source-neutral event that caused them, but they are not modeled
as additional source-neutral children.

## Source-Neutral and Generator-Owned Fields

### Source-Neutral Fields

Source-neutral fields describe the activity in terms of users, hosts, services, protocols, paths, and outcomes. They
should remain useful even when multiple generators consume the same event.

Examples:

- `source_host_id`
- `destination_host_id`
- `service_id`
- `method`
- `path`
- `status_code`
- `query_name`
- `resolved_addresses`

### Shared Detail Context

Some fields are source-neutral because multiple source-specific generators must agree on them. A scenario author may
provide these details for exact control. Concise scenarios may omit them and use deterministic defaults. The target
architecture supplies those defaults through shared enrichment before source-specific generators run.

Current implementation: `NetworkContext`, `DnsContext`, and `HttpContext` carry authored overrides on expanded events.
Zeek derives omitted defaults and flow keys inside its writer; there is no shared enrichment pass yet. The precedence
and ownership rules below describe the target for additional writers. NAT context is also future work.

Examples:

- Client ephemeral source ports for concrete network flows.
- Normalized flow keys or five-tuples.
- NAT translations when the environment models NAT.
- Shared byte and packet estimates when several sources observe the same flow.
- HTTP user-agent, HTTP version, response size, and other request facts that may appear in Zeek, Apache, proxy, or
  firewall-adjacent records.

Precedence:

1. Authored shared details win.
2. Deterministic enrichment fills omitted shared details.
3. Source-specific generators derive only source-native values that do not need cross-source agreement.

Shared detail context may live directly on expanded events or in an immutable sidecar object linked by event ID,
correlation ID, or flow ID. Source-specific generators should consume this context, not mutate the original event after
the first generator notices a missing value.

### Generator-Owned Fields

Generator-owned fields are created by source-specific generators. They should not be required in source-neutral events.

Examples:

- Zeek `uid`
- Zeek connection state rendering
- Apache source-native size rendering when it is not backed by shared HTTP response size
- Apache combined-log escaping of a shared user agent
- auditd serial numbers
- Firewall policy names, rule numbers, action strings, and NAT renderings
- source-native timestamp strings
- source-native packet or byte counters when they are not backed by shared flow estimates

The source-neutral event may provide enough context for a generator to derive these values deterministically from a
seed, but it should not store source-native fields as required model data.

## Event Type Definitions

## `dns_lookup`

### Purpose

Models a host querying a DNS resolver for a name.

### Required Fields

| Field | Type | Description |
| --- | --- | --- |
| `source_host_id` | string | Host making the DNS query. |
| `query_name` | string | Requested DNS name. |
| `query_type` | string | DNS record type, such as `A`. |

### Optional Fields

| Field | Type | Description |
| --- | --- | --- |
| `actor_user_id` | string | User associated with the lookup. |
| `destination_host_id` | string | DNS resolver host, derived from `service_id` when possible. |
| `service_id` | string | DNS service, usually `svc-dns`. |
| `resolved_addresses` | list[string] | Successful answer addresses. |
| `rcode` | string | Source-neutral DNS response code. |
| `parent_event_id` | string | Login or other parent event that caused the lookup. |

### Validation Notes

- `source_host_id` must resolve to a known environment host.
- Authored input may omit resolver fields when the environment has a default DNS service.
- Expanded events should include `destination_host_id` and `service_id` for the resolver.
- `destination_host_id` must resolve to a known resolver host when provided.
- `service_id` must resolve to a DNS service on the resolver host when provided.
- Known internal names should resolve through the environment DNS records.
- A successful lookup for an internal `A` record should include at least one address.
- A failed lookup should not include successful answer addresses.

### Canonical Scenario Use

- `evt-benign-web-001` resolves `web-server-01.internal`.
- `evt-misuse-web-002` resolves `web-server-01.internal`.

## `network_connection`

### Purpose

Models a transport-level connection or flow between two hosts.

### Required Fields

| Field | Type | Description |
| --- | --- | --- |
| `source_host_id` | string | Host that initiated the connection. |
| `source_ip` | string | Source IP address used for the connection. |
| `destination_ip` | string | Destination IP address. |
| `destination_port` | integer | Destination service port. |
| `network_protocol` | string | Transport protocol, such as `tcp` or `udp`. |

### Optional Fields

| Field | Type | Description |
| --- | --- | --- |
| `actor_user_id` | string | User associated with the connection. |
| `service_id` | string | Environment service targeted by the connection. |
| `destination_host_id` | string | Known destination host derived from service or address lookup. |
| `application_protocol` | string | Application protocol, such as `http`. |
| `parent_event_id` | string | DNS lookup or other parent event. |

### Validation Notes

- Authored service traffic may specify `service_id` instead of destination host, IP, and port.
- Expanded events should include destination host, IP, port, and protocol when they are known.
- `source_host_id` and `destination_host_id` must resolve to known hosts when provided.
- `source_ip` should match the source host unless explicitly overridden.
- `destination_ip` should match the destination host or service bind address.
- `destination_port` should match `service_id` when a service is provided.
- Internal traffic should be checked against sensor visibility when future network records are expected.
- A successful TCP connection should target a defined service for canonical scenarios.

### Canonical Scenario Use

- `evt-benign-web-002` connects `linux-ws-01` to `web-server-01` on TCP port `80`.
- `evt-misuse-web-003` connects `linux-ws-01` to `web-server-01` on TCP port `80`.

## `web_request`

### Purpose

Models one HTTP request to a modeled web service.

### Required Fields

| Field | Type | Description |
| --- | --- | --- |
| `source_host_id` | string | Client host that made the request. |
| `service_id` | string | Web service targeted by the request. |
| `method` | string | HTTP method, such as `GET`. |
| `path` | string | Request path without scheme or host. |

### Optional Fields

| Field | Type | Description |
| --- | --- | --- |
| `actor_user_id` | string | User associated with the request. |
| `destination_host_id` | string | Server host derived from `service_id` during expansion. |
| `url` | string | Full URL when useful for authoring or output. |
| `query_string` | string | Query component without the leading `?`. |
| `status_code` | integer | HTTP response status code, inferred from route defaults when omitted. |
| `request_headers` | object | Source-neutral request header hints. |
| `response_content_type` | string | Source-neutral response content type hint. |
| `metadata.download_classification` | string | `download` when the path is classified as a download. |
| `metadata.file_name` | string | File name inferred from a download path. |
| `parent_event_id` | string | Network connection used for the request. |

### Validation Notes

- `service_id` must resolve to an HTTP service.
- Authored input may omit `destination_host_id` because the service maps to a target host.
- Expanded events should include `destination_host_id` derived from `service_id`.
- `destination_host_id` must match the service target host when provided.
- `path` should resolve to a known route unless the scenario intentionally models an unknown route.
- `status_code` should match the route default unless the scenario explicitly overrides it.
- `method` and `path` together should identify the route behavior.
- Authored YAML may omit `status_code` when the environment route provides a default.
- Expanded source-neutral events should include `status_code` so downstream writers do not repeat route lookup.
- Generator-owned web-server records are derived from this event and the service implementation.
- Authors should not create `apache_request`, `nginx_request`, or similar source-specific child events.

### Download Classification

A `web_request` is classified as a download when the path appears to target a file that is not an HTML page.

Rules:

- A path ending in `/` is a directory or page request.
- A path with no file extension is a page or route request.
- A path ending in `.html` or `.htm` is an HTML page request.
- A path ending in another extension is a download.

Examples:

| Path | Classification |
| --- | --- |
| `/` | page |
| `/admin` | page |
| `/about.html` | page |
| `/admin/archive.tar.gz` | download |
| `/reports/data.csv` | download |

When a path is classified as a download, the event should keep `event_type` as `web_request`. Implementations may add
`metadata.download_classification: download` and `metadata.file_name` for answer keys or normalized JSONL output.

### Canonical Scenario Use

- `evt-benign-web-003` requests `/` and is classified as a page request.
- `evt-misuse-web-004` requests `/admin` and is classified as a page request.
- `evt-misuse-web-005` requests `/admin/archive.tar.gz` and is classified as a download.

## `linux_local_login`

### Purpose

Models a local Linux login attempt on a host.

### Required Fields

| Field | Type | Description |
| --- | --- | --- |
| `actor_user_id` | string | User attempting the login. |
| `target_host_id` | string | Host receiving the login attempt. |
| `login_method` | string | Login mechanism, such as `local_console`. |

### Optional Fields

| Field | Type | Description |
| --- | --- | --- |
| `source_host_id` | string | Remote origin host when the login is not local console activity. |
| `source_ip` | string | Remote origin IP when available. |
| `metadata.activity_classification` | string | Scenario classification such as `suspicious`. |
| `parent_event_id` | string | Prior event that caused the login attempt. |

### Validation Notes

- `actor_user_id` must resolve to a known environment user.
- `target_host_id` must resolve to a known environment host.
- Successful login requires the target host to appear in the user's `login_hosts`.
- Failed login may reference invalid account placement only when the scenario explicitly models misuse or probing.
- Future auditd records may be generated only for hosts with auditd-capable logging profiles.

### Canonical Scenario Use

- `evt-misuse-web-001` models suspicious but valid use of Alice's local account on `linux-ws-01`.

## `tls_connection`

### Purpose

Models TLS negotiation layered over a network connection.

### Required Fields

| Field | Type | Description |
| --- | --- | --- |
| `source_host_id` | string | Client host initiating TLS. |
| `destination_host_id` | string | Server host receiving TLS. |
| `service_id` | string | TLS-capable service. |
| `tls_version` | string | Negotiated TLS version. |

### Optional Fields

| Field | Type | Description |
| --- | --- | --- |
| `server_name` | string | SNI or intended server name. |
| `certificate_subject` | string | Source-neutral certificate subject hint. |
| `certificate_issuer` | string | Source-neutral certificate issuer hint. |
| `parent_event_id` | string | Network connection used for TLS. |

### Validation Notes

- This event is reserved for HTTPS or other TLS scenarios.
- It is not required by the current canonical scenarios because `svc-web-http` uses plain HTTP.
- The parent should usually be a successful `network_connection`.
- Certificate hashes, Zeek TLS IDs, and source-native TLS fields are generator-owned.

## `process_execution`

### Purpose

Models a process execution on a host.

### Required Fields

| Field | Type | Description |
| --- | --- | --- |
| `actor_user_id` | string | User context that started the process. |
| `source_host_id` | string | Host where the process ran. |
| `process_name` | string | Executable name. |
| `command_line` | string | Source-neutral command line. |

### Optional Fields

| Field | Type | Description |
| --- | --- | --- |
| `working_directory` | string | Process working directory. |
| `parent_process_name` | string | Parent process name when useful. |
| `exit_code` | integer | Process exit code when modeled. |
| `parent_event_id` | string | Login or other event that caused the process. |

### Validation Notes

- This event is reserved for later host activity scenarios.
- It is not required by the current canonical scenarios.
- `actor_user_id` must be valid on `source_host_id` for successful local execution.
- auditd process IDs, serial numbers, and syscall-specific fields are generator-owned.

## Scenario Coverage

| Scenario | Event Types |
| --- | --- |
| `scenario-benign-internal-web` | `dns_lookup`, `network_connection`, `web_request` |
| `scenario-local-account-misuse-web` | `linux_local_login`, `dns_lookup`, `network_connection`, `web_request` |

These are expanded event types. Authored scenario input may contain only the user-visible `web_request` events and the
login event. No canonical scenario requires `apache_request` or `file_download`; Apache records and download labels
are derived from `web_request`.

## Phase 1 Implementation Notes

- Implement the common envelope before event-specific models.
- Keep event models source-neutral and validate them against the environment template.
- Keep generator-owned values out of required event fields.
- Start with exact canonical scenario fixtures before adding random or noisy generation.
- Implement helper expansion from `web_request` to DNS and connection events for known internal services.
- Defer `tls_connection` and `process_execution` implementation unless Phase 1 explicitly expands.
- Generate generic normalized JSONL from these source-neutral events as the official MVP output family.

## Defaults and Deferrals

- Implement only the four scenario-required event types first.
- Keep `tls_connection` and `process_execution` documented but deferred until a scenario requires them.
- Compute download classification during event expansion and store it in `metadata` for normalized JSONL.
- Allow authored `web_request` input to omit `status_code` when a known route provides the default.
- Require expanded `web_request` events to include `status_code`.
