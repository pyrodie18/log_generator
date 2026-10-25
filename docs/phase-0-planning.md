# Phase 0 Planning

Status: complete. This document records the original Phase 0 scope and decisions. Phases 1 through 3 are also
implemented; see `docs/phase-3-planning.md` for the current handoff. Phase-specific exclusions below describe the
original sequencing, not the current feature set.

## Purpose

Phase 0 finalizes the minimum viable product boundary for the synthetic log generator before source-neutral core
implementation begins. The phase should produce implementation-ready design artifacts, not production code.

The planning goal is to make the first implementation small enough to build and validate while still proving the core
architecture:

- Source-neutral events can describe meaningful activity.
- A small modeled environment can constrain realistic activity.
- Canonical scenarios can compile into deterministic event sequences.
- Output paths and metadata can support later source-specific generators, human inspection, and downstream ingestion.
- Zeek schema research has a clear target for the first source-specific generator.

## Phase 0 Scope

### In Scope

- Define the first normalized event taxonomy.
- Specify the `linux-mini-lab` environment template in implementation-ready detail.
- Define two canonical MVP scenarios.
- Draft the initial YAML scenario schema.
- Draft the parser-friendly output directory contract and manifest expectations.
- Confirm the Zeek 8.2.x schema source and identify first Zeek streams.
- Record open decisions, risks, and acceptance criteria for moving into Phase 1.

### Out of Scope

- Implementing core models, generators, validators, or output writers.
- Building SIEM-specific collector, parser, index, pipeline, or dashboard configuration.
- Supporting Windows, Active Directory, cloud identity, vendor-specific firewall, proxy, router, or endpoint products in
  the MVP.
- Producing statistically realistic noise models.
- Freezing the plugin API for long-term compatibility.
- Requiring ATT&CK metadata on every event or scenario.

## MVP Boundary

The MVP should focus on one environment, a small event taxonomy, two deterministic scenarios, and enough output
structure to support later generators.

The first useful implementation target after Phase 0 is:

1. Load or construct the `linux-mini-lab` environment.
2. Create source-neutral events for a benign web scenario and a local account misuse scenario.
3. Preserve deterministic event IDs, correlation IDs, and timestamps from the scenario seed.
4. Emit generic JSON Lines for the normalized events.
5. Leave source-specific Zeek, Apache, auditd, and firewall generation for later phases.

This boundary keeps Phase 1 focused on the domain model rather than source-specific log fidelity.

## Workstreams

### Workstream 1: Normalized Event Taxonomy

Objective: define the first source-neutral events with fields precise enough for core modeling and future generator
expansion.

Phase 1 required event types:

- `dns_lookup`
- `network_connection`
- `web_request`
- `linux_local_login`

Reserved early event types:

- `tls_connection`
- `process_execution`

Required planning tasks:

- Define a common event envelope shared by every event type.
- Define required and optional fields for each event type.
- Define status values such as `success`, `failure`, `denied`, and `unknown`.
- Define how parent and child events are represented.
- Define how correlation IDs differ from event IDs.
- Define which fields are source-neutral and which must be deferred to generator-owned extensions.
- Define how web-server records, such as Apache access records, are generated from `web_request` events.
- Define how download behavior is inferred from `web_request` paths.

Expected artifact:

- `docs/event-taxonomy-draft.md`

Acceptance criteria:

- Each MVP event type has a concise purpose statement.
- Each MVP event type lists required fields, optional fields, and validation notes.
- No event type requires Zeek-specific, Apache-specific, or auditd-specific fields.
- The taxonomy supports the two canonical scenarios without introducing extra event types.

### Workstream 2: `linux-mini-lab` Environment Template

Objective: describe the first environment template with enough detail to become fixtures and model instances in
Phase 1.

Environment inventory:

| ID | Type | Role | Network Zone | Address | Logging Coverage |
| --- | --- | --- | --- | --- | --- |
| `linux-ws-01` | host | workstation | `workstation-vlan` | `10.10.10.11` | auditd |
| `linux-ws-02` | host | workstation | `workstation-vlan` | `10.10.10.12` | auditd |
| `web-server-01` | host | web server | `server-vlan` | `10.10.20.21` | Apache, auditd |
| `lab-dns-01` | host | DNS resolver | `server-vlan` | `10.10.20.53` | none |
| `zeek-sensor-01` | sensor | passive network sensor | `monitoring-vlan` | `10.10.30.31` | Zeek |
| `boundary-fw-01` | network device | boundary firewall | workstation, server, internet | `10.10.10.1`, `10.10.20.1`, `203.0.113.10` | firewall |

Initial users:

| Username | Display Name | Home Host(s) | Account Type | Notes |
| --- | --- | --- | --- | --- |
| `alice` | Alice | `linux-ws-01` | local user | Primary user for canonical scenarios. |
| `bob` | Bob | `linux-ws-01` | local user | Benign background actor. |
| `carol` | Carol | `linux-ws-02` | local user | Benign background actor. |

Required planning tasks:

- Assign stable IP ranges and host addresses.
- Define hostnames, FQDNs, and aliases.
- Define local account availability per host.
- Define Apache service details for `web-server-01`.
- Define Zeek sensor visibility boundaries.
- Define network device interfaces and policy rules for derived firewall telemetry.
- Define environment lookup rules for users, hosts, services, and IP addresses.
- Define which impossible actions should be rejected during validation.
- Define deterministic IDs for hosts, users, networks, services, network devices, policy rules, and log sources.

Expected artifact:

- `docs/linux-mini-lab-template.md`

Acceptance criteria:

- Every canonical scenario can reference hosts, users, services, and sources from the template.
- Every host has a stable ID, hostname, role, network zone, and IP address.
- Every user has explicit valid login hosts.
- Sensor visibility is clear enough to explain why Zeek records should or should not exist.
- Network device policy is clear enough to explain why firewall records should or should not exist.

### Workstream 3: Canonical Scenarios

Objective: define two concrete scenarios that drive the first implementation and tests.

Scenario 1: benign internal web browsing.

- Actor: `alice`
- Source host: `linux-ws-01`
- Destination service: Apache on `web-server-01`
- Expected expanded source-neutral events:
  - `dns_lookup`
  - `network_connection`
  - `web_request`
- Expected future records:
  - Zeek `dns.log`
  - Zeek `conn.log`
  - Zeek `http.log`
  - Apache `access.log`

Scenario 2: local account misuse followed by suspicious internal web access.

- Actor: `alice` or attacker-controlled use of `alice`
- Source host: `linux-ws-01`
- Destination service: Apache on `web-server-01`
- Expected expanded source-neutral events:
  - `linux_local_login`
  - `dns_lookup`
  - `network_connection`
  - `web_request`
- Expected future records:
  - auditd authentication record on `linux-ws-01`
  - Zeek `dns.log`
  - Zeek `conn.log`
  - Zeek `http.log`
  - Apache `access.log`
  - answer-key record identifying the suspicious step

Required planning tasks:

- Give each scenario a stable ID and display name.
- Define timestamps as absolute values or relative offsets from scenario start.
- Define deterministic scenario seed expectations.
- Define expected parent-child event relationships.
- Define expected correlation behavior across events.
- Define expected validation checks.
- Define which metadata belongs in a hidden answer key versus generated logs.

Expected artifact:

- `docs/canonical-scenarios.md`

Acceptance criteria:

- Each scenario can be represented in Python and YAML without ambiguity.
- Each scenario has deterministic expected event counts.
- Each scenario identifies future source-specific records without requiring those records in Phase 1.
- The attack-style scenario includes optional ATT&CK fields without making them mandatory framework fields.

### Workstream 4: YAML Scenario Schema Draft

Objective: define an author-friendly scenario format that maps cleanly to source-neutral events.

Required planning tasks:

- Define top-level fields such as `name`, `seed`, `environment`, `time_range`, `output_families`, `events`, and
  `attack_chain`.
- Define timestamp syntax for absolute timestamps and relative offsets.
- Define event references for dependencies, such as `after` and `delay`.
- Define validation behavior for unknown users, hosts, services, and event fields.
- Define error message expectations for common authoring mistakes.
- Define when YAML should remain simple and when Python authoring should be recommended instead.

Expected artifact:

- `docs/scenario-yaml-schema-draft.md`

Acceptance criteria:

- Both canonical scenarios can be expressed in the draft YAML format.
- The schema avoids source-specific log fields.
- The schema leaves room for later noise profiles without requiring noise in the MVP.
- The schema has clear validation behavior for missing or unknown references.

### Workstream 5: Output Directory and Manifest Contract

Objective: define the first parser-friendly output layout before implementing any writer.

Initial path contract:

```text
output/
  manifest.json
  logs/
    <generating_source_id>/
      <log_family>/
        <log_stream>
  metadata/
    ground-truth.jsonl
    scenario-manifest.json
```

Required planning tasks:

- Define path component naming rules and filesystem-safe IDs.
- Define where the official generic normalized JSONL output lives.
- Define manifest fields for generated files, formats, timestamp fields, source IDs, and scenario IDs.
- Define ground-truth file behavior, including when it is omitted.
- Define whether empty log files are created for streams with zero records.
- Define how output manifests stay SIEM-neutral and human-readable.

Expected artifact:

- `docs/output-contract-draft.md`

Acceptance criteria:

- A future writer can implement the directory contract without guessing path rules.
- The manifest describes generated files without assigning platform-specific routing, normalization, or pipeline
  configuration.
- The layout can separate Zeek, Apache, auditd, firewall, and generic JSONL records by source and family.

### Workstream 6: Zeek Schema Research

Objective: identify the authoritative schema references for the first Zeek generator.

Required planning tasks:

- Confirm the current Zeek 8.2.x log field references for `conn.log`, `dns.log`, `http.log`, and TLS or SSL logs.
- Identify field differences that matter for Zeek 8.0.x LTS compatibility.
- Decide whether the first Zeek generator emits native TSV, JSONL, or both.
- Define the minimum field set needed for plausible web browsing records.
- Record any Zeek-specific values that must be generated by the plugin rather than stored in source-neutral events.

Expected artifact:

- `docs/zeek-schema-notes.md`

Acceptance criteria:

- The first Zeek implementation can begin with known target fields and formats.
- Zeek-specific generated fields such as `uid` are identified as plugin-owned.
- Any compatibility gaps between Zeek 8.2.x and Zeek 8.0.x are documented.

## Decision Log

Phase 0 should maintain a decision log so implementation work does not reopen settled questions casually.

Initial decisions to record:

| Decision | Proposed Default | Reason |
| --- | --- | --- |
| First environment | `linux-mini-lab` | Small enough to model and validate. |
| First implementation output | Generic normalized JSONL | Easy to diff and validate before source generators. |
| First source-specific target | Zeek 8.2.x | Current feature target already named by architecture plan. |
| Secondary Zeek target | Zeek 8.0.x LTS where practical | Keeps future compatibility in view without blocking MVP. |
| SIEM configuration | Out of scope | Project emits files and metadata; consuming environments configure ingestion. |
| ATT&CK metadata | Optional in MVP | Useful for attacks but too heavy as a universal requirement. |
| Plugin API stability | Not frozen in MVP | Early generators should prove the API before compatibility promises. |
| Apache request authoring | Generated from web requests | Generators inspect the endpoint and emit source records. |
| Download modeling | Inferred from `web_request` path | A single web request can be classified as a download. |
| Generic normalized JSONL | Official MVP output family | Provides a stable output before source generators exist. |
| Service references | Prefer `service_id` in authored events | Destination host and address fields can be derived. |
| Helper events | Generated by default for web requests | Authors can still manually model DNS or connections. |
| Manifest scope | Describe files and source systems only | Keeps output metadata SIEM-neutral and human-readable. |
| First Zeek output format | Native Zeek-style TSV by default | Preserves source fidelity; Zeek JSONL can be added later if useful. |
| First Zeek streams | `conn.log`, `dns.log`, `http.log` | Covers the canonical web browsing records without adding TLS or file streams early. |
| YAML loading schedule | Defer YAML parsing to Phase 2 | Keeps Phase 1 focused on source-neutral models, expansion, validation, and generic JSONL output. |

Open decisions after step 7 review:

- None. New decisions should be recorded here with an owner, default, or explicit deferral before they affect Phase 1.

## Tightened MVP Boundary

Step 7 closes the remaining Phase 0 decisions and narrows the first implementation to the smallest useful source
neutral core.

Phase 1 should include:

- Python object models or fixtures for the `linux-mini-lab` environment.
- Source-neutral event envelope and the four scenario-required event types.
- Deterministic identifiers, timestamps, ordering, correlation IDs, and parent event links.
- Helper expansion from authored web activity into DNS, connection, and web request events for the canonical services.
- Semantic validation against the environment template.
- Generic normalized JSON Lines output and the MVP manifest contract.
- Unit tests based on the two canonical expanded scenarios.

Phase 1 should not include:

- YAML file parsing or a public authoring CLI.
- Source-specific Zeek, Apache, auditd, or firewall log generation.
- Noise profiles, random background activity, or statistically realistic traffic modeling.
- TLS, process execution, Windows, Active Directory, cloud, proxy, or vendor-specific firewall support.
- A stable plugin API.

The YAML schema remains a reviewed design artifact for Phase 2. Phase 1 may use Python constructors, fixtures, or
in-memory scenario definitions as long as the resulting expanded events match the canonical scenario documents.

## Phase 0 Sequence

Recommended order:

1. Draft the `linux-mini-lab` environment template.
2. Draft the two canonical scenarios.
3. Draft the normalized event taxonomy from the scenarios.
4. Draft the YAML schema using the scenarios as examples.
5. Draft the output directory and manifest contract.
6. Research and document Zeek schema notes.
7. Review open decisions and tighten the MVP boundary.
8. Create the Phase 1 implementation task breakdown in `docs/phase-1-task-breakdown.md`.

This order keeps the design grounded in concrete scenarios instead of expanding the taxonomy abstractly.

## Validation Approach

Phase 0 is documentation-heavy, but its deliverables should still be validated.

Validation checks:

- Each canonical scenario references only entities defined in `linux-mini-lab`.
- Every required event field in the taxonomy appears in at least one scenario or has a clear reason to exist.
- YAML examples map to the same conceptual events as the prose scenario definitions.
- Output paths can be derived from the planned log sources without reading event payloads.
- Zeek notes identify the fields needed for the first planned web browsing records.

Repository checks after doc updates:

```bash
uv lock --check
uv run --frozen pytest
uv run --frozen flake8 src tests
```

## Risks and Mitigations

| Risk | Impact | Mitigation |
| --- | --- | --- |
| Phase 0 grows too broad | Delays implementation | Tie each artifact to the two canonical scenarios. |
| Event taxonomy is too narrow | Requires churn in Phase 1 | Allow extensions and document known follow-up events. |
| Event taxonomy is too broad | Makes core models vague | Do not add events that the canonical scenarios do not need. |
| YAML schema becomes too magical | Hard to validate and explain | Keep MVP YAML explicit and defer parser implementation to Phase 2. |
| Zeek research blocks all planning | Slows Phase 0 | Treat Zeek notes as a generator prerequisite. |
| SIEM hints become accidental config | Scope creep | Manifest describes files but does not generate ingestion config. |
| Attack metadata becomes mandatory too early | Burdens benign scenarios | Keep ATT&CK fields optional. |

## Phase 0 Exit Criteria

Phase 0 is complete. Its exit criteria were:

- `docs/linux-mini-lab-template.md` exists and defines all MVP entities and source coverage.
- `docs/canonical-scenarios.md` exists and defines two deterministic scenarios.
- `docs/event-taxonomy-draft.md` exists and covers all events required by the scenarios.
- `docs/scenario-yaml-schema-draft.md` exists and includes examples for both scenarios.
- `docs/output-contract-draft.md` exists and defines path and manifest expectations.
- `docs/zeek-schema-notes.md` exists and identifies the first Zeek schema targets.
- `docs/phase-1-task-breakdown.md` exists and turns the Phase 1 handoff into ordered implementation tasks.
- Open decisions have owners, defaults, or explicit deferrals.
- Phase 1 tasks can be written directly from the Phase 0 artifacts.
- The full test suite and flake8 checks pass after documentation updates.

## Phase 1 Handoff

Phase 1 should start only after Phase 0 has narrowed the core model enough to implement without guessing.

Expected Phase 1 starting tasks:

- Create source-neutral entity models for hosts, users, services, networks, and log sources.
- Create the `linux-mini-lab` fixture or template from the Phase 0 environment document.
- Create event envelope and event type models from the taxonomy draft.
- Add deterministic ID, scenario seed, and correlation helpers.
- Add helper expansion for the two canonical web scenarios.
- Add semantic validation for unknown users, unknown hosts, invalid local logins, and impossible service references.
- Add generic normalized JSONL output and a minimal manifest writer.
- Add tests for the two canonical scenarios at the source-neutral event level.
- Defer YAML parsing until Phase 2; Phase 1 tests should construct scenarios through Python fixtures or model objects.
