# Phase 1 Task Breakdown

## Purpose

This document turns the Phase 0 planning artifacts into an implementable Phase 1 task list. Phase 1 should prove the
source-neutral core before adding YAML parsing or source-specific generators.

Primary inputs:

- `docs/phase-0-planning.md`
- `docs/linux-mini-lab-template.md`
- `docs/canonical-scenarios.md`
- `docs/event-taxonomy-draft.md`
- `docs/output-contract-draft.md`

## Phase 1 Scope

Phase 1 includes:

- Source-neutral environment and event models.
- The `linux-mini-lab` fixture or in-code template.
- Deterministic IDs, timestamps, ordering, correlation IDs, and parent links.
- Expansion for the two canonical scenarios.
- Semantic validation against the environment.
- Generic normalized JSON Lines output and a minimal manifest.
- Tests for the canonical source-neutral scenarios and output contract.

Phase 1 excludes:

- YAML parsing.
- Zeek, Apache, auditd, or firewall source-specific log generation.
- Noise profiles or statistically realistic random activity.
- TLS, process execution, Windows, Active Directory, cloud, proxy, and vendor-specific firewall support.
- A stable plugin API.

## Recommended Order

### Task 1: Create Core Package Structure

Goal: add the modules needed for source-neutral modeling without overbuilding the later plugin architecture.

Suggested files:

- `src/log_generator/core/__init__.py`
- `src/log_generator/core/environment.py`
- `src/log_generator/core/events.py`
- `src/log_generator/core/scenarios.py`
- `src/log_generator/core/validation.py`
- `src/log_generator/output/__init__.py`
- `src/log_generator/output/jsonl.py`
- `src/log_generator/output/manifest.py`

Acceptance criteria:

- New modules import cleanly.
- Public classes and functions have docstrings that match the repository standard.
- Existing package imports remain backward compatible.
- `python -m pytest` and `flake8 --max-line-length=120 .` pass.

### Task 2: Model `linux-mini-lab`

Goal: represent the Phase 0 environment as stable Python data that validation and expansion can query.

Implement:

- Network zones: `workstation-vlan`, `server-vlan`, `monitoring-vlan`, and `internet`.
- Hosts: `linux-ws-01`, `linux-ws-02`, `web-server-01`, `lab-dns-01`, and `zeek-sensor-01`.
- Network device: `boundary-fw-01`.
- Users: `user-alice`, `user-bob`, `user-carol`, and `user-www-data`.
- Services: `svc-web-http`, `svc-web-ssh`, and `svc-dns`.
- DNS records, HTTP routes, logging profiles, sensor visibility, and firewall rules from the environment document.

Acceptance criteria:

- Lookup helpers resolve host IDs, hostnames, FQDNs, IP addresses, user IDs, usernames, service IDs, and DNS records.
- `lab-dns-01` exists as a normal environment host without a logging profile.
- HTTP route lookup returns default status codes for `/`, `/admin`, and `/admin/archive.tar.gz`.
- Tests assert the exact canonical host, user, service, DNS, route, and logging-profile references.

### Task 3: Implement Source-Neutral Event Models

Goal: define the common event envelope and the four scenario-required event types.

Implement:

- `dns_lookup`
- `network_connection`
- `web_request`
- `linux_local_login`

Recommended model behavior:

- Use timezone-aware UTC datetimes.
- Keep source-specific fields such as Zeek `uid`, Apache byte counts, auditd serial numbers, and firewall rule names
  out of required event fields.
- Allow event-specific metadata and optional ATT&CK context without requiring either on every event.
- Require expanded `web_request` events to include `status_code`.

Acceptance criteria:

- Event instances serialize to dictionaries suitable for JSON Lines output.
- Required fields match `docs/event-taxonomy-draft.md`.
- Optional fields can be omitted without producing source-specific placeholder values.
- Tests cover successful creation for each required event type.

### Task 4: Add Deterministic Scenario Primitives

Goal: make canonical scenarios reproducible before adding YAML authoring.

Implement:

- Scenario identity, name, seed, environment reference, and time range.
- Deterministic event ordering by timestamp and authored or expanded sequence order.
- Correlation ID preservation.
- Parent event references.
- Stable helper event IDs for canonical scenario assertions.

Acceptance criteria:

- Same scenario input produces the same expanded event IDs and ordering across runs.
- Parent event IDs always point to earlier events in the same scenario.
- Correlation IDs remain stable and shared across each canonical scenario.

### Task 5: Implement Web Helper Expansion

Goal: expand authored web activity into the source-neutral event sequence required by the canonical scenarios.

Implement:

- `web_request` expansion for `svc-web-http`.
- Generated DNS lookup against `svc-dns` when no compatible lookup exists.
- Generated network connection to the target service when no compatible connection exists.
- Connection reuse for later compatible `web_request` events in the same correlation.
- Download classification from `web_request.path`.

Acceptance criteria:

- `scenario-benign-internal-web` expands to exactly 3 events.
- `scenario-local-account-misuse-web` expands to exactly 5 events.
- The misuse scenario's second web request reuses the first HTTP connection as its parent.
- `/admin/archive.tar.gz` keeps `event_type: web_request` and receives download metadata.
- Helper event timestamps match the canonical scenario documents.

### Task 6: Add Semantic Validation

Goal: reject impossible or inconsistent source-neutral activity before output writing.

Implement validation for:

- Unknown users, hosts, services, DNS names, and routes.
- Invalid local login hosts.
- Web requests to non-HTTP services.
- Source and destination addresses that conflict with environment references.
- `service_id` values that conflict with destination host, IP, port, or protocol.
- Parent references that do not resolve to earlier events.
- Missing successful DNS answers for successful internal A lookups.

Acceptance criteria:

- Validation errors include the scenario ID, field path, invalid value, and actionable reason.
- The two canonical scenarios validate successfully.
- Tests cover at least one failure for unknown user, unknown host, invalid login host, unknown service, bad route, and
  unresolved parent event.

### Task 7: Implement Generic Normalized JSONL Output

Goal: write expanded source-neutral events to the official MVP output path.

Implement:

- `logs/source-neutral-core/generic-normalized/events.jsonl`.
- Stable ISO 8601 UTC timestamp rendering.
- One JSON object per expanded event.
- Event sorting by timestamp, then sequence order.
- Safe path component validation.

Acceptance criteria:

- Benign output writes 3 event records.
- Misuse output writes 5 event records.
- Generic records include the common envelope and event-specific fields.
- Source-specific generator-owned fields are absent unless they are valid source-neutral metadata.
- The writer does not create source-specific Zeek, Apache, auditd, or firewall files.

### Task 8: Implement Minimal Manifest and Metadata Output

Goal: describe generated artifacts without adding SIEM-specific routing or parser configuration.

Implement:

- `manifest.json`.
- `metadata/scenario-manifest.json`.
- `metadata/ground-truth.jsonl` only when answer-key records exist.
- `omitted_streams` as an empty list unless coverage reporting is intentionally implemented.

Acceptance criteria:

- Manifest file entries match files actually written.
- Record counts match line counts.
- Benign output omits `ground-truth.jsonl`.
- Misuse output includes the `suspicious_internal_web_download` ground-truth record.
- Manifest fields follow `docs/output-contract-draft.md`.

### Task 9: Add Canonical Scenario Tests

Goal: make the Phase 0 scenarios executable regression fixtures.

Test targets:

- Every canonical environment reference resolves through `linux-mini-lab`.
- Benign scenario event count, ordering, correlation ID, and parent links.
- Misuse scenario event count, ordering, correlation ID, parent links, optional ATT&CK metadata, and download metadata.
- Generic JSONL output paths and record counts.
- Manifest paths, record counts, scenario IDs, and omitted ground-truth behavior.

Acceptance criteria:

- Tests assert exact IDs and timestamps from `docs/canonical-scenarios.md`.
- Tests run without network access.
- `python -m pytest` passes.
- `flake8 --max-line-length=120 .` passes.

## Suggested Milestones

### Milestone 1: Environment and Events

Includes tasks 1 through 3.

Exit criteria:

- `linux-mini-lab` is queryable.
- Required source-neutral events can be created and serialized.
- Basic model tests pass.

### Milestone 2: Expansion and Validation

Includes tasks 4 through 6.

Exit criteria:

- The canonical scenarios expand to exact source-neutral event sequences.
- Semantic validation accepts canonical scenarios and rejects representative invalid inputs.

### Milestone 3: Output and Fixtures

Includes tasks 7 through 9.

Exit criteria:

- Generic normalized JSONL and manifest output match the Phase 0 contract.
- Canonical scenario tests provide the baseline for Phase 2 YAML parsing and later source-specific generators.

## Phase 1 Completion Criteria

Phase 1 is complete when:

- Both canonical scenarios can be constructed without YAML parsing.
- Expanded source-neutral events match the Phase 0 scenario documents.
- Generic normalized JSONL and minimal manifest output are written to the documented paths.
- Ground truth is emitted only for scenarios with answer-key records.
- No source-specific Zeek, Apache, auditd, or firewall files are generated.
- The full test suite passes.
- `flake8 --max-line-length=120 .` passes.
