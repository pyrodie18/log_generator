# Synthetic Log Generator Architecture Plan

## Executive Summary

This project should evolve into a source-neutral Python library for generating high-fidelity synthetic logs. The library should let users define synthetic environments, benign scenarios, background noise, and controlled attack sequences, then emit plausible correlated logs across enabled sources such as Zeek, Windows Event Logs, firewalls, routers, proxies, DNS servers, endpoint tools, cloud services, and future plugin-provided sources.

The core architecture should not be coupled to any one log source or downstream SIEM. Zeek, Windows, firewall,
proxy, and other generators should be plugins that translate source-neutral events into source-specific records. The
project should emit well-organized file trees and clear metadata that a human can understand and any downstream SIEM
pipeline can map into its own ingestion model.

Initial implementation should prioritize:

- Schema-valid logs.
- Plausible logs.
- Correlated realistic logs across sources.
- Deterministic replay using random seeds.
- Parser-friendly directory output.

Statistically realistic generation should be designed for but not required in the first implementation.

## Current Design Decisions

- First Zeek fidelity target: the Zeek 8.2.x field set documented in `docs/zeek-schema-notes.md`.
- Secondary Zeek compatibility target: Zeek 8.0.x LTS where practical.
- Windows Event Log output target: clear, structured JSON files that preserve Windows event semantics.
- SIEM ingestion configuration is out of scope. The project only needs to produce understandable directory structures,
  source-native or structured files, and metadata that downstream tooling can map into its own ingestion model.
- Output logs should be grouped by generating source first, then by log family and stream. The directory path should make the source identifiable without reading a metadata file.
- First built-in example environment: `linux-mini-lab`, with two Linux workstations, one Linux Apache web server, one
  DNS resolver, one Zeek sensor, and one boundary firewall across workstation, server, monitoring, and internet zones.
  Authentication uses local Linux accounts only; LDAP, Active Directory, and other centralized identity providers are
  out of scope for the first template.
- The generator should write an optional answer-key file at `output/metadata/ground-truth.jsonl` for demos, training, and CTF-style exercises.
- The generator should write a dataset manifest at `output/manifest.json` that inventories generated files and records
  human-readable parsing hints without generating SIEM configuration.
- MITRE ATT&CK metadata is optional for the MVP. Attack-style scenarios may include technique labels, but benign
  scenarios and core event models should not require them.
- Plugin API stability: early implementation may favor iteration over long-term backward compatibility.

## Implementation Status and Roadmap Alignment

The implementation has moved some capabilities earlier than the original roadmap described. Future work should treat
the phase-specific planning documents as the more current implementation handoff:

- Phase 0 is complete as planning work. The detailed artifacts live under `docs/`.
- Phase 1 is complete for the current MVP source-neutral core: `linux-mini-lab`, deterministic canonical scenarios,
  source-neutral event expansion, semantic validation, generic normalized JSONL, output metadata, and manifest writing.
- Phase 2 is complete for the current YAML and CLI workflow: one scenario per YAML file, deterministic timing,
  canonical YAML fixtures, answer-key metadata, public generation helpers, and `log-generator generate`.
- Generic normalized JSONL and the parser-friendly output tree are already implemented. They should no longer be
  planned as separate future phases.
- Phase 3 is complete as the first source-specific generator: Zeek native-style TSV for `conn.log`, `dns.log`, and `http.log`.
  The detailed handoff is `docs/phase-3-planning.md`.
- Authored shared contexts are implemented, but omitted flow, DNS, and HTTP defaults are still derived within the
  Zeek writer. A shared source-neutral enrichment pass remains follow-up work before other writers need those defaults.
- Apache, auditd, firewall, proxy, noise, richer attack sequencing, and stable plugin APIs remain future work after
  the Zeek path proves the first source-specific generator boundary.

## Recommended Architecture

The abstractions, event fields, plugin interfaces, and package layout below describe the long-term design. They are
not all implemented APIs. Use the status section above, the phase-specific handoff, and the YAML/output references
for the current behavior.

Use a layered architecture:

1. Authoring layer: Python API and YAML scenario files.
2. Domain layer: environments, entities, scenarios, attack chains, and noise profiles.
3. Event layer: normalized source-neutral activity events.
4. Timeline layer: ordering, causality, jitter, clock skew, and reproducibility.
5. Generation layer: plugin registry and source-specific log generators.
6. Validation layer: schema validation, source validation, and cross-source consistency validation.
7. Output layer: JSON Lines, source-native files, syslog-style files, and parser-friendly directory trees.

The core framework should own activity meaning, causality, and environment consistency. Plugins should own
source-specific terminology, fields, formats, validation, and record expansion.

## Core Abstractions

### Environment

An `Environment` describes the synthetic world where activity occurs. It contains hosts, users, networks, domains, services, applications, security controls, and log source coverage.

Responsibilities:

- Hold the authoritative inventory.
- Prevent impossible activity, such as a user logging into a nonexistent host.
- Provide lookup helpers for entities, IPs, services, domains, and controls.
- Define default behavior profiles for users and hosts.
- Define which log sources are visible for each part of the environment.

### Entity

An `Entity` is the base abstraction for named objects in the synthetic world.

Common fields:

- Stable ID.
- Human-readable name.
- Entity type.
- Labels.
- Metadata.
- Optional ground-truth role, such as `victim`, `attacker`, `domain_controller`, or `crown_jewel`.

### Host

A `Host` represents an endpoint or compute resource such as a workstation, server, domain controller, cloud resource,
attacker system, or application host.

Important fields:

- Hostname.
- FQDN.
- IP addresses.
- Operating system.
- Network zone.
- Roles.
- Installed applications.
- Running services.
- Logging coverage.

### Network Device

A `NetworkDevice` represents routed or inspected connectivity between zones, such as a firewall, router, proxy, or
other network appliance.

Important fields:

- Device ID.
- Device type.
- Interfaces, each with a zone and IP address.
- Policy rules for allowed or denied traffic.
- NAT behavior.
- Logging coverage.

### User

A `User` represents a human, service account, administrator, attacker identity, or synthetic principal.

Important fields:

- Username.
- Display name.
- Domain or identity provider.
- Groups and roles.
- Normal login hosts.
- Normal working hours.
- Credential state.
- Risk labels.

### Network, Subnet, and Zone

Network abstractions model address space and trust boundaries.

Responsibilities:

- Define valid IP ranges.
- Capture internal, DMZ, external, cloud, VPN, and attacker zones.
- Support routing and policy decisions.
- Constrain random generation to plausible source and destination pairs.

### Service and Application

Services represent reachable network endpoints. Applications represent user-facing or host-local software.

Examples:

- HTTPS service on an internal web app.
- SMB on a file server.
- SSH on a Linux host.
- Browser on a workstation.
- PowerShell on a Windows host.

### Identity Provider and Active Directory Domain

Identity abstractions model authentication context.

Responsibilities:

- Define domains, realms, users, groups, and domain controllers.
- Support Windows logon activity.
- Support Kerberos, NTLM, LDAP, and cloud identity events over time.

### Security Control

A `SecurityControl` represents telemetry-producing or access-controlling infrastructure.

Examples:

- Zeek sensor.
- Firewall.
- Proxy.
- Endpoint detection tool.
- Windows Event Forwarding.
- DNS server logging.
- Cloud audit logging.

### Scenario

A `Scenario` is intentional activity authored by a user.

Examples:

- Alice browses to a website.
- Bob logs into a Linux workstation with a local account.
- An attacker scans internal systems.
- Malware calls back to attacker infrastructure.

Scenarios should compile into normalized events before plugin generation.

### Event

An `Event` is the source-neutral representation of activity. Events can be authored directly, derived from a scenario, generated as background noise, or produced as child events of a higher-level event.

Examples:

- `dns_lookup`
- `network_connection`
- `web_request`
- `tls_connection`
- `linux_local_login`
- `windows_logon`
- `process_execution`
- `lateral_movement_attempt`

The implemented MVP event set is intentionally narrow. Authors should model HTTP activity with `web_request`; Apache
or nginx records are generator output, and download behavior is inferred from the `web_request` path.

### Attack Chain and Attack Step

An `AttackChain` is a controlled adversary story composed of ordered or partially ordered `AttackStep` objects.

Each step should include:

- Objective.
- Actor.
- Target.
- Required preconditions.
- Expected telemetry.
- Success or failure outcome.
- Optional ATT&CK metadata.
- Optional answer-key metadata.

### Log Source

A `LogSource` is a configured telemetry source instance, such as `zeek/site-a`, `windows/domain-controller-security`, or `firewall/perimeter-fw-01`.

### Log Generator

A `LogGenerator` is a plugin that transforms normalized events into source-specific records.

Responsibilities:

- Declare supported event types.
- Declare supported schemas and output formats.
- Validate source-specific context.
- Emit zero, one, or many records per event.
- Provide source-specific validators.

### Log Record

A `LogRecord` is a concrete generated record ready for validation and output.

It should contain:

- Source-specific payload.
- Source metadata.
- Source classification.
- Host.
- Timestamp.
- Original event ID.
- Correlation ID.
- Scenario ID.
- Optional ground-truth labels.

### Timeline

The `Timeline` schedules events, preserves causality, and applies realistic timestamp behavior.

### Correlation ID

A `CorrelationId` links related events and records across sources. For example, a web browsing action may produce DNS, Zeek conn, Zeek HTTP, proxy, firewall, and endpoint telemetry with the same correlation lineage.

### Noise Profile

A `NoiseProfile` describes stochastic background activity using traffic mixes, volume, time curves, user behavior, host behavior, and realism constraints.

### Output Writer

An `OutputWriter` writes validated records to files, streams, archives, or parser-friendly directories.

### Schema Validator

A `SchemaValidator` verifies field presence, field types, enum values, timestamp formats, and source-specific
requirements.

## Event Model Design

The normalized event model should be source-neutral and expressive enough to describe behavior before it becomes source-specific telemetry.

Recommended common fields:

- `id`: stable event identifier.
- `type`: normalized event type.
- `scenario_id`: scenario that produced the event.
- `correlation_id`: shared ID for related activity.
- `parent_event_id`: parent event, if this event was derived.
- `child_event_ids`: child events, if known.
- `timestamp`: event start time.
- `duration`: event duration.
- `status`: success, failure, denied, unknown. A distinct partial outcome is a possible future extension.
- `severity`: informational, low, medium, high, critical.
- `actor`: person, process, account, or attacker identity responsible for the activity.
- `user`: user account involved.
- `source_host`: source host.
- `destination_host`: destination host.
- `source_ip`: source IP.
- `source_port`: source port when a concrete flow has been assigned one.
- `destination_ip`: destination IP.
- `domain`: DNS, Windows, cloud, or identity domain.
- `protocol`: protocol such as DNS, HTTP, HTTPS, SMB, Kerberos, SSH, or LDAP.
- `port`: destination port.
- `url`: full URL where applicable.
- `fqdn`: domain name queried or accessed.
- `process`: process name and path.
- `command_line`: command execution details.
- `file`: path, size, hash, and classification metadata.
- `auth_context`: authentication mechanism, realm, logon type, and credential outcome.
- `network_context`: shared flow facts such as bytes, packets, direction, zone, NAT, and sensor visibility.
- `attack_context`: optional ATT&CK tactic, technique, tool, stage, and objective.
- `exercise_context`: ground-truth labels, hints, difficulty, and answer-key markers.

Source-specific details should be produced by generators. For example, Zeek `uid`, Windows `EventID`, and firewall vendor action strings should not be required in the core event model.

Some values are source-neutral because multiple source generators must agree on them, even though most scenario authors
will not want to write them by hand. Examples include client ephemeral source ports, normalized flow five-tuples, NAT
translations, shared byte or packet estimates, DNS transaction context, HTTP user-agent strings, HTTP versions, and
response sizes.

The precedence should be:

1. Authored details win when a scenario provides them.
2. Deterministic source-neutral enrichment fills any omitted shared details.
3. Source-specific generators derive only source-native fields that do not need cross-source agreement.

This is the target ownership model. Phase 3 honors authored `network`, `dns`, and `http` contexts but derives omitted
defaults in `log_generator.output.zeek`; it does not yet populate shared generated defaults on source-neutral events.

This lets a user plan every detail of a scenario when needed while keeping concise scenarios reproducible and sane by
default. Shared details may live directly on expanded events or in immutable flow, DNS, or HTTP context linked to those
events. Source-specific generators should consume that shared context rather than mutating the original event after
they discover a missing field.

Source-specific extension fields may be allowed under plugin-owned namespaces, such as:

```text
extensions.zeek
extensions.windows
extensions.siem
```

The core should not depend on these extensions for normal behavior.

## Timeline and Causality Model

The timeline should support:

- Single events.
- Multi-step scenarios.
- Long-running background noise.
- Concurrent benign activity.
- Attack chains unfolding over minutes, hours, or days.
- Source-specific timestamp offsets.
- Clock skew.
- Log source latency.
- Deterministic replay.

Store all internal timestamps as timezone-aware UTC datetimes. Output writers may render local time if a source format requires it.

Use a causality graph rather than only a linear list. This allows events to be concurrent while preserving required ordering.

Examples of ordering constraints:

- DNS lookup occurs before HTTP request.
- TLS handshake occurs before HTTPS application data.
- Windows authentication occurs before interactive user activity.
- Process creation occurs before endpoint network connection.
- Firewall allow record aligns with the same flow represented in Zeek `conn.log`.
- Domain controller authentication events align with workstation logon events.

Randomness should be deterministic. The scenario seed is the only user-authored seed and should be split into scoped
random streams internally, for example:

```text
rng/scenario/<scenario_id>
rng/noise/<profile_id>
rng/plugin/<plugin_name>/<event_id>
```

This reduces accidental churn when new plugins or events are added.

## Plugin Model Design

Plugins should register generators with the framework. Initial implementation can use explicit registration. Later versions can use Python package entry points.

Generator descriptors should include:

- Generator name.
- Source family.
- Supported event types.
- Supported output formats.
- Supported schema versions.
- Required event fields.
- Optional event fields.
- Configuration model.
- Visibility assumptions.
- Whether the generator emits zero, one, or many records per event.
- Source-specific validators.

Example conceptual descriptor:

```text
name: zeek
source_family: network_sensor
supported_events:
  - dns_lookup
  - network_connection
  - web_request
  - tls_connection
output_formats:
  - zeek-tsv
  - jsonl
schema_versions:
  - zeek-8.2
  - zeek-8.0-lts
```

Unsupported events should be handled explicitly:

- `ignore`: no record expected for this source.
- `unsupported`: source could theoretically emit telemetry, but plugin does not support it yet.
- `missing_context`: event lacks fields needed for generation.
- `not_visible`: source has no visibility due to environment coverage.

This distinction matters for debugging scenario coverage.

## Cross-Source Correlation

The system should keep records consistent across sources using shared event lineage and environment-derived facts.

Consistency rules:

- Same source IP across Zeek, firewall, proxy, and endpoint records.
- DNS query precedes related HTTP or TLS connection.
- Firewall flow matches Zeek `conn.log` five-tuple where both sources observe the same flow.
- Proxy destination matches the requested URL or host.
- Linux local login activity matches the user and host represented in auditd records.
- Apache access records match the requested URL and the Zeek-observed HTTP flow.
- Future Windows authentication records should match user, workstation, domain, and domain controller.
- Endpoint process records line up with network telemetry when appropriate.
- Attack activity preserves stage, tool, actor, and target labels.
- Noise generation respects environment constraints.

Recommended metadata:

- `scenario_id`
- `event_id`
- `parent_event_id`
- `correlation_id`
- `attack_chain_id`
- `attack_step_id`
- `ground_truth_labels`
- `source_visibility`

Validation should include cross-source checks for major scenario types.

## Scenario Definition Format

Support both Python and YAML.

Python should be best for advanced users, tests, dynamic generation, and programmatic control. YAML should be best for reusable demos, training labs, and CTF authoring.

JSON can be supported later as an intermediate machine-readable representation, but Python and YAML should be the primary user interfaces.

### Benign Python Example

```python
env = Environment.from_template("linux-mini-lab")

scenario = Scenario("benign-web", seed=42)
scenario.user("alice").on("linux-ws-01").browses("http://web-server-01.internal/")

run = GeneratorRun(
    environment=env,
    scenario=scenario,
    output_families=["generic-normalized", "zeek"],
    output=DirectoryOutput("./output"),
)
```

The Python example above is still aspirational API syntax. The current implemented public workflow uses scenario
objects, YAML fixtures, and `log-generator generate`; stable high-level builder syntax should wait until more source
families prove the right abstraction.

### Attack Python Example

```python
env = Environment.from_template("linux-mini-lab")

attack = AttackChain("local-account-misuse", seed=42)
attack.step("credential-use").linux_local_login(
    user="alice",
    host="linux-ws-01",
    success=True,
)
attack.step("internal-web-access").web_request(
    user="alice",
    source_host="linux-ws-01",
    service="svc-web-http",
    path="/admin",
)
attack.step("suspicious-admin-download").web_request(
    source_host="linux-ws-01",
    service="svc-web-http",
    path="/admin/archive.tar.gz",
)
```

### Benign YAML Example

```yaml
schema_version: scenario/v0.1
id: benign-web
name: Benign Web
seed: 42
environment:
  id: linux-mini-lab
  version: "0.1"
time_range:
  start: "2026-06-27T09:00:00Z"
  end: "2026-06-27T10:00:00Z"
output_families:
  - generic-normalized
events:
  - id: evt-benign-web-001
    type: web_request
    at: "+5m"
    actor: user-alice
    source_host: linux-ws-01
    service: svc-web-http
    method: GET
    path: /
```

### Attack YAML Example

```yaml
schema_version: scenario/v0.1
id: local-account-misuse
name: Local Account Misuse
seed: 1337
environment:
  id: linux-mini-lab
  version: "0.1"
time_range:
  start: "2026-06-27T09:15:00Z"
  end: "2026-06-27T09:30:00Z"
output_families:
  - generic-normalized
events:
  - id: credential-use
    type: linux_local_login
    at: "2026-06-27T09:15:00Z"
    actor: user-alice
    target_host: linux-ws-01
    login_method: local_console
    status: success
  - id: internal-web-access
    type: web_request
    after: credential-use
    delay: "3m"
    actor: user-alice
    source_host: linux-ws-01
    service: svc-web-http
    method: GET
    path: /admin
  - id: suspicious-admin-download
    type: web_request
    after: internal-web-access
    delay: "8m"
    actor: user-alice
    source_host: linux-ws-01
    service: svc-web-http
    method: GET
    path: /admin/archive.tar.gz
    attack:
      technique_id: T1105
      technique_name: Ingress Tool Transfer
attack_chain:
  - id: step-download
    name: Archive download
    primary_event_id: suspicious-admin-download
    technique_id: T1105
    technique_name: Ingress Tool Transfer
```

Phase 3 allows YAML scenarios to add `zeek` to `output_families`. Apache, auditd, firewall, and proxy families remain
rejected until their generators exist.

### Noise YAML Example

Noise profiles are documented for the future design. The current YAML implementation rejects `noise_profiles` with an
explicit unsupported-feature message.

```yaml
schema_version: scenario/v0.1
id: office-background
name: Office Background
seed: 9001
environment:
  id: linux-mini-lab
  version: "0.1"
time_range:
  start: "2026-06-27T08:00:00Z"
  end: "2026-06-27T18:00:00Z"
events: []
noise_profiles:
  - id: light-business-hours-web
    time_profile: business_hours
    actor_pool:
      - user-bob
      - user-carol
```

## First Environment Template

The first built-in environment should be intentionally small and Linux-only. This keeps the initial implementation
focused while still providing room for host identity, users, network segmentation, network device policy, local
authentication, Apache web logs, auditd logs, Zeek network visibility, and derived firewall telemetry as source
families are added.

Template name: `linux-mini-lab`

Hosts:

- `linux-ws-01`: Linux workstation on the workstation VLAN, with local users `alice` and `bob`.
- `linux-ws-02`: Linux workstation on the workstation VLAN, with local user `carol`.
- `web-server-01`: Linux web server on a separate internal server VLAN, running Apache.
- `lab-dns-01`: Linux DNS resolver on the server VLAN.
- `zeek-sensor-01`: Zeek sensor passively observing workstation and server VLAN traffic.

Network devices:

- `boundary-fw-01`: Boundary firewall with interfaces in the workstation VLAN, server VLAN, and external internet zone.

Network layout:

- Workstation VLAN: contains `linux-ws-01` and `linux-ws-02`.
- Server VLAN: contains `web-server-01` and `lab-dns-01`.
- Monitoring VLAN: contains `zeek-sensor-01`.
- Internet: external zone reached through `boundary-fw-01`.
- Sensor visibility: `zeek-sensor-01` sees workstation-to-server and server-to-workstation traffic.
- Firewall policy: `boundary-fw-01` allows workstation DNS and HTTP flows to the server VLAN and web traffic to the
  internet; denied traffic can still produce firewall telemetry when the matching policy rule logs.

Authentication model:

- All user activity uses local Linux accounts.
- LDAP, Active Directory, Kerberos, NTLM, and cloud identity are out of scope for the first environment template.

Planned log families:

- `zeek-sensor-01/zeek`: Zeek `conn.log`, `dns.log`, `http.log`, and TLS-related logs where applicable.
- `linux-ws-01/auditd`: Local Linux authentication and process-relevant audit records.
- `linux-ws-02/auditd`: Local Linux authentication and process-relevant audit records.
- `web-server-01/apache`: Apache access and error logs.
- `web-server-01/auditd`: Local Linux authentication and process-relevant audit records on the web server.
- `boundary-fw-01/firewall`: Firewall allow and deny traffic records.

## Noise Generation Design

Noise generation should create normalized events first. Source-specific records should still be produced by plugins.

Noise profile capabilities:

- Weighted random event selection.
- Per-host behavior.
- Per-user behavior.
- Time-of-day curves.
- Weekday and weekend patterns.
- Volume controls.
- Burstiness controls.
- Long-tail randomness.
- Source visibility constraints.
- Signal-to-noise controls for exercises.

Important realism constraints:

- Hosts should communicate with services that make sense for their role.
- Workstations should generate user browsing and local account activity; the web server should primarily generate
  Apache and server-side auditd activity.
- External systems should not initiate internal SMB unless VPN, NAT, compromise, or exposure is modeled.
- Failed or denied traffic should be present but not dominate by default.
- Attack activity should blend into normal activity without making exercises useless.

## Attack Scenario Design

Attack scenarios should represent telemetry outcomes, not real exploit execution.

Supported concepts:

- Multiple stages.
- Success and failure paths.
- Branching logic.
- Delays between steps.
- Attacker infrastructure.
- Victim assets.
- Credential use and misuse.
- Toolmarks and artifacts.
- Defender-visible logs.
- Ground-truth answer keys.
- Hints.
- Difficulty levels.

Attack metadata should support ATT&CK-style fields without requiring them for every event:

- `tactic`
- `technique_id`
- `technique_name`
- `procedure`
- `tool`
- `stage`

Difficulty levels can tune:

- Noise volume.
- Obviousness of indicators.
- Number of failed attacker actions.
- Label visibility in generated answer keys.
- Whether logs include clean correlation metadata or only hidden manifest metadata.

## Directory Layout Strategy

The project should not manage SIEM ingestion configuration. It should not generate or maintain platform-specific
collector inputs, parser rules, index definitions, pipelines, dashboards, or search-time field extraction
configuration. Those concerns belong to the environment that consumes the generated files.

The project should stay SIEM-neutral by producing deterministic, well-organized directory trees and clear metadata.
The directory structure should be understandable to a human first. A downstream SIEM can then map paths, file formats,
and metadata into its own ingestion model.

The output path should identify the generating source directly. A generating source is the system, device, sensor, or
service instance that would have written the log in a real environment. For example, `zeek-sensor-01` may only contain
Zeek logs, `web-server-01` may contain Apache, auditd, and application logs, and `boundary-fw-01` may contain firewall
logs. The manifest can add detail, but it must not be required to determine which source generated a file.

Recommended path contract:

```text
output/logs/<generating_source_id>/<log_family>/<log_stream>
```

Where:

- `generating_source_id` is a stable, filesystem-safe source identifier such as `zeek-sensor-01`, `web-server-01`,
  `linux-ws-01`, `linux-ws-02`, or `boundary-fw-01`.
- `log_family` is the source family or subsystem, such as `zeek`, `windows`, `apache`, `auditd`, `firewall`, or
  `proxy`.
- `log_stream` is the concrete stream or file, such as `conn.log`, `security.jsonl`, `access.log`, or `audit.log`.

Recommended output layout:

```text
output/
  manifest.json
  logs/
    zeek-sensor-01/
      zeek/
        conn.log
        dns.log
        http.log
        ssl.log
    linux-ws-01/
      auditd/
        audit.log
    linux-ws-02/
      auditd/
        audit.log
    web-server-01/
      apache/
        access.log
        error.log
      auditd/
        audit.log
  metadata/
    ground-truth.jsonl
    scenario-manifest.json
```

Each generated record or file family should have enough metadata for a human or downstream tooling to understand the
dataset:

- Generating source ID.
- Log family.
- Log stream.
- Subject host, if the record describes a different host than the system that generated the log.
- Timestamp field or timestamp position.
- Time zone assumption.
- File format.
- Scenario ID.
- Generator version.

The directory structure should avoid mixing unrelated generating sources in one file. It should also avoid mixing
unrelated log families under the same source. For example, Apache access logs and auditd logs from `web-server-01`
should live under the same generating source directory but in separate log-family directories. Zeek connection logs,
Windows Security events, proxy records, and firewall records should be emitted separately so external ingestion
tooling can assign source-specific parsing rules from the path alone.

Windows Event Log output should prioritize clear structured JSON that preserves event IDs, providers, channels, hosts,
timestamps, and record payloads. Platform-specific decisions about routing, enrichment, normalization, pipelines, or
parsing configuration remain out of scope.

## Output Format Strategy

Priority order:

1. JSON Lines for generic records, manifests, ground truth, structured Windows output, and tests.
2. Zeek native-style TSV logs for Zeek fidelity.
3. Parser-friendly monitored file directory structure.
4. Syslog-style files for firewalls, routers, proxies, and appliances.
5. CSV or TSV for simple tabular sources.
6. XML-like Windows Event representations later if needed.
7. Vendor-specific formats through plugins.

JSON Lines should be the first generic output because it is easy to validate, diff, test, and ingest.

## Schema Fidelity and Validation Strategy

Validation should happen in layers.

### Source Schema Validation

Check:

- Required fields.
- Optional fields.
- Field types.
- Enum values.
- Timestamp formats.
- Source-specific naming.
- Version-specific differences.

### Semantic Validation

Check:

- Referenced hosts and users exist.
- IPs belong to the modeled environment.
- Services use plausible ports and protocols.
- Authentication results are plausible.
- Event ordering constraints are satisfied.

### Cross-Source Validation

Check:

- Zeek and firewall records agree on network five-tuples.
- DNS precedes web activity.
- Proxy URL matches network destination.
- Linux local login activity aligns with auditd records for the generating host.
- Apache access logs from `web-server-01` align with Zeek HTTP and connection records.
- Endpoint process execution aligns with network behavior.

### Testing Strategy

Use:

- Unit tests for event models and plugins.
- Snapshot tests for deterministic output.
- Golden sample logs for source fidelity.
- Property-based tests for random generation invariants.
- Fixture environments and scenarios.
- Real sample comparison where allowed.

The validation framework should explicitly distinguish:

- Schema-valid.
- Plausible.
- Correlated realistic.
- Statistically realistic.

## Proposed Package Layout

The current implementation uses a flatter package layout than this long-term sketch. That is acceptable while the core,
YAML workflow, and first output writers are still small. Future package splits should be driven by real complexity,
especially after multiple source-specific generators exist.

```text
src/log_generator/
  __init__.py
  core/
    __init__.py
    correlation.py
    entities.py
    environment.py
    events.py
    timeline.py
  scenarios/
    __init__.py
    api.py
    models.py
    yaml_loader.py
  noise/
    __init__.py
    profiles.py
    scheduler.py
  attacks/
    __init__.py
    chains.py
    metadata.py
  plugins/
    __init__.py
    base.py
    registry.py
  generators/
    __init__.py
    generic_json.py
    zeek/
      __init__.py
      generator.py
      schemas.py
      validators.py
    apache/
      __init__.py
      generator.py
      schemas.py
      validators.py
    auditd/
      __init__.py
      generator.py
      schemas.py
      validators.py
    windows/
      __init__.py
      generator.py
      schemas.py
      validators.py
    firewall/
      __init__.py
      generator.py
      schemas.py
      validators.py
  output/
    __init__.py
    jsonl.py
    directory_layout.py
    syslog.py
  validation/
    __init__.py
    schemas.py
    semantic.py
  testing/
    __init__.py
    fixtures.py
docs/
  examples/
tests/
  fixtures/
```

## Development Roadmap

The roadmap below supersedes the original phase ordering. The original plan placed generic JSONL and manifest output
after YAML authoring, but those capabilities are already part of the implemented Phase 1 and Phase 2 baseline.

### Phase 0: Design Decisions and Open Questions

Goal: finalize MVP boundaries.

Status: complete.

Major tasks:

- Define initial normalized event taxonomy.
- Document the `linux-mini-lab` environment template.
- Define first two canonical scenarios.
- Define first parser-friendly output directory layout.
- Confirm Zeek schema source for Zeek 8.2.x.

Deliverables:

- Architecture plan.
- Event taxonomy draft.
- Scenario schema draft.
- Output directory layout draft.

Risks:

- Too much design before implementation.
- Event taxonomy becomes too broad.

Acceptance criteria:

- MVP scope is small enough to implement.
- First scenarios are concrete and testable.

### Phase 1: Source-Neutral Core Framework

Goal: implement environment, event, correlation, validation, generic output, and manifest primitives.

Status: complete for the current MVP.

Major tasks:

- Add `linux-mini-lab` environment models.
- Add the MVP source-neutral events: `dns_lookup`, `network_connection`, `web_request`, and `linux_local_login`.
- Add deterministic event IDs, correlation IDs, parent links, ordering, and scenario expansion.
- Add semantic validation for environment references and event relationships.
- Add generic normalized JSONL output.
- Add parser-friendly output paths, scenario metadata, ground-truth metadata, and the top-level manifest.

Deliverables:

- Core package under `src/log_generator/core/`.
- Generic output helpers under `src/log_generator/output/`.
- Canonical Python scenario fixtures.
- Unit and regression tests for source-neutral events, environment validation, generic output, and manifests.

Risks:

- Core models become too generic or too complex.
- Generic output becomes confused with source-specific output.

Acceptance criteria:

- Source-neutral events can be created, scheduled, linked, and validated.
- Canonical scenarios produce stable generic normalized JSONL and manifest output.

### Phase 2: Scenario Model and Authoring Interface

Goal: support YAML scenario definitions and shell generation using the Phase 1 core.

Status: complete for deterministic single-scenario YAML files.

Major tasks:

- Add YAML parser.
- Add schema validation for YAML.
- Add clear error messages.
- Add deterministic timestamp and dependency resolution.
- Convert authored YAML events into Phase 1 source-neutral primitives.
- Add public YAML loading and generation helpers.
- Add CLI generation through `log-generator generate`.

Deliverables:

- Canonical benign YAML example.
- Canonical local-account-misuse YAML example.
- YAML validation tests.
- CLI tests.
- README usage notes.

Risks:

- YAML becomes too rigid.
- YAML conversion duplicates source-neutral expansion logic.
- Source-specific output sneaks into the authoring phase before its generator exists.

Acceptance criteria:

- Example scenarios load into normalized events deterministically.
- YAML-generated canonical output matches the Phase 1 Python fixture output.
- Expected authoring errors produce concise validation messages.

### Phase 3: First Source-Specific Generator, Zeek

Goal: generate native-style Zeek TSV logs for common web activity.

Status: complete. See `docs/phase-3-planning.md` for the implemented scope and acceptance criteria.

Major tasks:

- Allow YAML and Python scenarios to request `zeek`.
- Implement Zeek TSV schema definitions and header rendering.
- Add author-overridable source-neutral flow, DNS, and HTTP contexts for client source ports, byte or packet counts,
  DNS transaction details, HTTP user agents, HTTP versions, and response sizes. Omitted defaults and flow keys are
  currently derived within the Zeek writer.
- Implement deterministic Zeek-owned values such as `uid`, Zeek file IDs, Zeek connection state, Zeek history, and TSV
  rendering details.
- Implement Zeek `conn.log`, `dns.log`, and `http.log` mapping from existing source-neutral events.
- Write Zeek files under `logs/zeek-sensor-01/zeek/`.
- Add Zeek file entries and useful omitted-stream entries to the manifest.

Deliverables:

- `src/log_generator/output/zeek.py` or equivalent.
- Zeek native-style TSV files.
- Canonical benign and misuse Zeek output tests.
- Manifest and CLI tests for Zeek-enabled runs.
- README usage notes for requesting Zeek output.

Risks:

- Zeek-specific assumptions leak into the core.
- Field fidelity is incomplete.
- Zeek stream linkage drifts, especially `uid` reuse between `conn.log`, `dns.log`, and `http.log`.

Acceptance criteria:

- A canonical web scenario produces plausible Zeek DNS, connection, and HTTP records.
- DNS and HTTP rows share `uid` values with their underlying `conn.log` rows.
- Generic-only output remains unchanged.

### Phase 4: Zeek Expansion or Linux Host Logs

Goal: broaden source-specific coverage after the first Zeek path proves the generator boundary.

Status: future.

Major tasks:

- Choose the next target from observed scenario needs:
  - Add Zeek `files.log` for HTTP downloads.
  - Add Zeek `ssl.log` for HTTPS/TLS scenarios.
  - Add auditd-style Linux local authentication records.
  - Add Apache access logs for `web-server-01`.
- Add any required source-neutral hints only when a real generator needs them.
- Extract shared default derivation from Zeek before an additional writer needs the same generated flow, DNS, or HTTP
  facts, and test that those values agree across outputs.
- Add source-specific validators and golden fixtures for the chosen target.

Deliverables:

- One additional source-specific stream or tightly related stream group.
- Cross-source consistency tests against existing generic and Zeek output.
- Updated documentation and output contract examples.

Risks:

- Expanding too many families at once slows validation and testing.
- Host-log requirements may expose missing source-neutral event context.

Acceptance criteria:

- The selected next stream produces stable, plausible records for a canonical scenario.
- Existing Phase 3 Zeek behavior remains stable.

### Phase 5: Background Noise Generation

Goal: generate realistic benign activity around scenarios.

Status: future.

Major tasks:

- Add traffic mix profiles.
- Add time-of-day behavior.
- Add per-host and per-user constraints.
- Add signal-to-noise controls.
- Add YAML support for supported noise profile fields.

Deliverables:

- Background noise YAML support.
- Deterministic noise tests.
- Cross-source noise validation for implemented source families.

Risks:

- Noise overwhelms exercise signal.
- Random generation creates impossible activity.

Acceptance criteria:

- Noise generation is reproducible and respects environment constraints.
- Answer-key metadata remains useful when noise is present.

### Phase 6: Linux Host Log Generators

Goal: generate Linux host logs for the initial `linux-mini-lab` template.

Status: future.

Major tasks:

- Implement auditd-style local authentication records.
- Implement auditd-style process-relevant records where scenario context requires them.
- Implement Apache access and error log generation for `web-server-01`.
- Correlate Linux host logs with Zeek-observed network activity.

Deliverables:

- Linux auditd log output.
- Apache access and error log output.
- Linux host log validators.

Risks:

- Linux audit and Apache formats are source-specific and can vary by distro or deployment.

Acceptance criteria:

- A local Linux login and web browsing scenario produces plausible auditd, Apache, and Zeek records.

### Phase 7: Firewall, Proxy, and Router Generators

Goal: add common infrastructure telemetry.

Status: future.

Major tasks:

- Implement firewall allow and deny flow records.
- Implement proxy request records.
- Implement router or network device syslog-style records.

Deliverables:

- Firewall JSONL or syslog output.
- Proxy JSONL output.
- Cross-source validation with Zeek.

Risks:

- Vendor-neutral formats may feel unrealistic.

Acceptance criteria:

- Web and denied-connection scenarios produce consistent Zeek, firewall, and proxy records.

### Phase 8: Attack Sequence Support

Goal: support controlled attack stories for demos and CTFs.

Status: partially started for metadata; future for richer sequencing.

Major tasks:

- Add richer attack chain models.
- Add step dependencies and branching.
- Expand ATT&CK metadata support.
- Keep answer-key output separate from generated source logs.
- Add difficulty controls.

Deliverables:

- Example attack chain.
- Ground-truth manifest.
- Attack telemetry across multiple sources.

Risks:

- Attack logs become too obvious or too unrealistic.

Acceptance criteria:

- A multi-stage attack produces coherent logs and an answer key.

### Phase 9: Plugin API and External Source Generators

Goal: stabilize the generator boundary after several built-in source families exist.

Status: future.

Major tasks:

- Extract common generator descriptors and registration.
- Define supported event-type declarations and unsupported-event behavior.
- Add package entry point discovery if needed.
- Document versioning and compatibility expectations.

Deliverables:

- Stable plugin interface.
- Example external generator.
- Plugin authoring documentation.

Risks:

- Freezing the API before source-family requirements are understood.

Acceptance criteria:

- A source generator can be added without changing core scenario or event code.

### Phase 10: Validation, Testing, Documentation, and Packaging

Goal: harden the project for long-term use.

Status: ongoing, with expanded work after additional source families exist.

Major tasks:

- Expand schema validation.
- Add fixture library.
- Add documentation examples.
- Add packaging metadata.
- Add CI checks.

Deliverables:

- Full test suite.
- Linting.
- Example datasets.
- User documentation.

Risks:

- Maintenance burden grows with each source.

Acceptance criteria:

- Tests and lint pass.
- Examples are reproducible.
- Plugin API is documented.

## Risks and Mitigations

| Risk | Mitigation |
| --- | --- |
| Core overfits to Zeek | Keep Zeek-specific fields in the Zeek plugin. Require normalized source-neutral events. |
| Scenario format is too rigid | Support Python for dynamic authoring and YAML for reusable scenarios. |
| Logs look valid but are semantically inconsistent | Add semantic and cross-source validators. |
| Attack logs are too obvious | Add difficulty controls and blend attacks into realistic noise. |
| Attack logs are too unrealistic | Model failed steps, delays, normal toolmarks, and environment constraints. |
| Noise overwhelms exercises | Add explicit signal-to-noise controls and answer-key support. |
| Schema fidelity is hard to maintain | Version schemas, use golden samples, and isolate validators by source. |
| Plugin API changes frequently | Accept churn during early design, then freeze only after built-in generators prove the API. |
| Too much complexity too early | Use the implemented generic output baseline, add one Zeek path, then expand. |
| Performance issues at large volume | Stream records and validate incrementally. |
| Downstream timestamp or line-breaking problems | Keep generated files separated by generating source and log family, document timestamp fields in the manifest, and avoid multiline formats unless the source requires them. |
| Lack of good sample logs | Use public samples where allowed and build high-quality synthetic fixtures over time. |

## Open Questions

1. How much ATT&CK metadata should be required?
   - Deferred. Revisit this when attack emulation and MITRE ATT&CK-style scenarios become part of the active
     implementation work.

## Recommended Next Steps

Phase 3 from `docs/phase-3-planning.md` is implemented: scenarios can request Zeek native-style TSV output for
`conn.log`, `dns.log`, and `http.log`, manifests describe generated and omitted Zeek streams, and README examples cover
`output_families: [generic-normalized, zeek]`.

The next source-specific phase should choose either Zeek `files.log`/`ssl.log` or Linux auditd/Apache based on the next
canonical scenario need. That work should preserve the current Phase 3 boundary: source-specific family names other
than `zeek` remain explicit unsupported errors until their writers exist.
