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

- First Zeek fidelity target: the current Zeek feature release line, currently Zeek 8.2.x.
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

## Recommended Architecture

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

Current Phase 0 planning narrows the MVP event set. Authors should model HTTP activity with `web_request`; Apache or
nginx records are generator output, and download behavior is inferred from the `web_request` path.

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
- `status`: success, failure, partial, denied, unknown.
- `severity`: informational, low, medium, high, critical.
- `actor`: person, process, account, or attacker identity responsible for the activity.
- `user`: user account involved.
- `source_host`: source host.
- `destination_host`: destination host.
- `source_ip`: source IP.
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
- `network_context`: bytes, packets, direction, zone, NAT, and sensor visibility.
- `attack_context`: optional ATT&CK tactic, technique, tool, stage, and objective.
- `exercise_context`: ground-truth labels, hints, difficulty, and answer-key markers.

Source-specific details should be produced by generators. For example, Zeek `uid`, Windows `EventID`, and firewall vendor action strings should not be required in the core event model.

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
    output_families=["zeek", "apache", "auditd", "firewall"],
    output=DirectoryOutput("./output"),
)
```

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
  - zeek
  - apache
  - auditd
  - firewall
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
  - zeek
  - apache
  - auditd
  - firewall
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

### Noise YAML Example

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
focused while still exercising host identity, users, network segmentation, network device policy, local authentication,
Apache web logs, auditd logs, Zeek network visibility, and derived firewall telemetry.

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

Initial log families:

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

### Phase 0: Design Decisions and Open Questions

Goal: finalize MVP boundaries.

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

Goal: implement environment, entity, event, correlation, and timeline primitives.

Major tasks:

- Add core models.
- Add deterministic seed handling.
- Add event lineage.
- Add basic validation.

Deliverables:

- Core package.
- Unit tests.
- Simple in-memory scenario expansion.

Risks:

- Core models become too generic or too complex.

Acceptance criteria:

- Source-neutral events can be created, scheduled, linked, and validated.

### Phase 2: Scenario Model and Authoring Interface

Goal: support Python and YAML scenario definitions.

Major tasks:

- Add Python scenario builder.
- Add YAML parser.
- Add schema validation for YAML.
- Add clear error messages.

Deliverables:

- Benign YAML example.
- Attack YAML example.
- Noise YAML example.

Risks:

- YAML becomes too rigid.
- Python API becomes too magical.

Acceptance criteria:

- Example scenarios load into normalized events deterministically.

### Phase 3: First Minimal Generic JSON Generator

Goal: emit normalized events as generic JSON Lines.

Major tasks:

- Add generic JSON generator.
- Add JSONL writer.
- Add snapshot tests.

Deliverables:

- Deterministic JSONL output.
- Initial manifest.

Risks:

- Generic output becomes confused with source-specific output.

Acceptance criteria:

- A simple scenario produces stable, testable JSONL.

### Phase 4: First Real Source Generator, Zeek

Goal: generate Zeek logs for common web activity.

Major tasks:

- Implement Zeek `dns.log`.
- Implement Zeek `conn.log`.
- Implement Zeek `http.log`.
- Add TLS-related records where scenario context supports them.
- Validate against Zeek 8.2.x field expectations.

Deliverables:

- Zeek native-style files.
- Zeek JSONL option if useful.
- Zeek validators.

Risks:

- Zeek-specific assumptions leak into the core.
- Field fidelity is incomplete.

Acceptance criteria:

- A web browsing event produces plausible Zeek DNS, conn, and HTTP records.

### Phase 5: Parser-Friendly Directory Output Writer

Goal: generate output trees that humans can inspect and downstream tools can monitor and parse.

Major tasks:

- Add directory layout writer.
- Add generating source, log family, log stream, subject host, timestamp, and format metadata.
- Add manifest.
- Keep ingestion configuration files out of scope.

Deliverables:

- Parser-friendly output directory.
- Documentation for the generated directory structure and manifest.

Risks:

- Timestamp ambiguity.
- Directory layout churn.

Acceptance criteria:

- Generated files are separated by generating source and log family.
- The manifest includes enough supplemental metadata for external ingestion tooling.

### Phase 6: Background Noise Generation

Goal: generate realistic benign activity around scenarios.

Major tasks:

- Add traffic mix profiles.
- Add time-of-day behavior.
- Add per-host and per-user constraints.
- Add signal-to-noise controls.

Deliverables:

- Background noise YAML support.
- Deterministic noise tests.

Risks:

- Noise overwhelms exercise signal.
- Random generation creates impossible activity.

Acceptance criteria:

- Noise generation is reproducible and respects environment constraints.

### Phase 7: Linux Host Log Generators

Goal: generate Linux host logs for the initial `linux-mini-lab` template.

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

### Phase 8: Firewall, Proxy, and Router Generators

Goal: add common infrastructure telemetry.

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

### Phase 9: Attack Sequence Support

Goal: support controlled attack stories for demos and CTFs.

Major tasks:

- Add attack chain models.
- Add step dependencies and branching.
- Add ATT&CK metadata support.
- Add answer-key output.
- Add difficulty controls.

Deliverables:

- Example attack chain.
- Ground-truth manifest.
- Attack telemetry across multiple sources.

Risks:

- Attack logs become too obvious or too unrealistic.

Acceptance criteria:

- A multi-stage attack produces coherent logs and an answer key.

### Phase 10: Validation, Testing, Documentation, and Packaging

Goal: harden the project for long-term use.

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
| Too much complexity too early | Implement generic JSON and one Zeek path before expanding. |
| Performance issues at large volume | Stream records and validate incrementally. |
| Downstream timestamp or line-breaking problems | Keep generated files separated by generating source and log family, document timestamp fields in the manifest, and avoid multiline formats unless the source requires them. |
| Lack of good sample logs | Use public samples where allowed and build high-quality synthetic fixtures over time. |

## Open Questions

1. How much ATT&CK metadata should be required?
   - Deferred. Revisit this when attack emulation and MITRE ATT&CK-style scenarios become part of the active
     implementation work.

## Recommended Next Steps

1. Define the first `linux-mini-lab` environment template.
2. Define the first normalized event taxonomy:
   - `dns_lookup`
   - `network_connection`
   - `web_request`
   - `linux_local_login`
   - `tls_connection` and `process_execution` are documented but deferred until a scenario needs them.
3. Define the first YAML schema for the canonical scenarios.
4. Implement the source-neutral core models.
5. Implement deterministic generic JSONL output.
6. Implement parser-friendly directory output and manifest metadata.
7. Add Zeek DNS, conn, and HTTP generation for the current Zeek release line.
8. Add auditd and Apache generators for the initial Linux-only template.
