# Phase 3 Planning

## Purpose

Phase 3 added the first source-specific output family: native-style Zeek TSV logs for the existing `linux-mini-lab`
canonical web scenarios. The phase turns already-expanded source-neutral events into plausible Zeek `conn.log`,
`dns.log`, and `http.log` records while preserving the Phase 1 and Phase 2 generic normalized JSONL workflow.

This plan follows the updated architecture roadmap in `docs/synthetic-log-generator-architecture.md`. Generic
normalized JSONL, parser-friendly manifest writing, YAML loading, and CLI generation already existed before Phase 3,
so Phase 3 focused on the first source-specific generator rather than replanning implemented generic output work.

## Primary Inputs

- `docs/phase-2-planning.md`
- `docs/zeek-schema-notes.md`
- `docs/output-contract-draft.md`
- `docs/canonical-scenarios.md`
- `docs/linux-mini-lab-template.md`
- Existing output modules under `src/log_generator/output/`
- Existing scenario loading and CLI workflow in `src/log_generator/scenario_yaml/` and `src/log_generator/cli.py`

## Phase 3 Scope

Phase 3 includes:

- Support for `output_families: [generic-normalized, zeek]` in YAML and Python scenarios.
- A Zeek output package that writes native-style TSV files.
- Generation of `conn.log`, `dns.log`, and `http.log` for traffic visible to `zeek-sensor-01`.
- Author-overridable source-neutral context for flow, DNS, and HTTP facts such as client source ports, byte or packet
  counts, DNS transaction context, HTTP user agents, HTTP versions, and response sizes.
- Deterministic source-neutral defaults for omitted shared context values, plus Zeek-owned values and rendering.
- Deterministic Zeek-owned values such as `uid`, Zeek file IDs, Zeek connection state, Zeek history, and TSV rendering
  details.
- Manifest file entries for generated Zeek files.
- Manifest omitted-stream entries when requested Zeek streams have zero records.
- Tests for canonical benign and misuse Zeek output.
- README documentation for requesting Zeek output.

Phase 3 excludes:

- `files.log`, `ssl.log`, `x509.log`, Apache, auditd, firewall, proxy, router, Windows, Active Directory, and cloud logs.
- New source-neutral event types.
- Batch generation across multiple YAML files.
- SIEM parser, collector, index, sourcetype, dashboard, or pipeline configuration.
- Exact packet capture fidelity.
- Site-specific Zeek packages or policy-loaded columns.
- Empty log-file creation for configured streams with no records.
- Zeek JSONL output.

## Phase 3 Deliverables

Implemented files or modules:

- `src/log_generator/output/zeek.py`
- `tests/test_zeek_output.py`
- Updates to `src/log_generator/output/manifest.py`
- Updates to `src/log_generator/scenario_yaml/`
- Output-family dispatch in `src/log_generator/output/registry.py`, used by manifest writing and CLI generation
- Zeek-enabled YAML fixture variants or targeted test fixtures
- README usage notes for `output_families: [generic-normalized, zeek]`

Zeek-specific rendering stays outside the core scenario and event modules. The source-neutral model does not expose
Zeek field names. Shared flow, DNS, and HTTP facts are authored or deterministically enriched before output writers
run, so generic JSONL and Zeek consume the same values. Zeek-specific IDs, connection state, history, and TSV
rendering remain in the Zeek writer.

## Task Completion Status

### Task 1: Accept Zeek as a Supported Output Family

Status: complete.

Goal: let authors request Zeek output without weakening unsupported-family validation.

Implemented:

- Replace the Phase 2 rejection for `zeek` with an allow-list entry.
- Keep `apache`, `auditd`, `firewall`, `proxy`, and custom families rejected with explicit unsupported messages.
- Preserve `generic-normalized` as the default when `output_families` is omitted.
- Preserve duplicate-family and unknown-family validation behavior.

Acceptance criteria:

- YAML containing `output_families: [generic-normalized, zeek]` loads successfully.
- YAML containing only `zeek` loads successfully if the implementation can write only requested families.
- `apache`, `auditd`, `firewall`, `proxy`, and custom family names still fail clearly.
- Existing Phase 2 canonical YAML tests continue to pass.

### Task 2: Define Zeek TSV Schemas and Header Rendering

Status: complete.

Goal: centralize Zeek stream schemas so record rendering, tests, and manifest entries share one source of truth.

Implemented:

- Field and type definitions for the MVP `conn`, `dns`, and `http` streams.
- Native Zeek header rows: `#separator`, `#set_separator`, `#empty_field`, `#unset_field`, `#path`, `#open`,
  `#fields`, `#types`, and `#close`.
- Deterministic `#open` and `#close` values derived from the run generation time or scenario time range.
- Timestamp formatting as epoch seconds with six fractional digits.
- Render helpers for Zeek unset values, empty values, booleans, sets, vectors, intervals, strings, integers, and counts.

Acceptance criteria:

- Each Zeek file starts with the expected header block.
- Fields and types align with `docs/zeek-schema-notes.md`.
- TSV rendering escapes or rejects values that cannot be represented safely.
- Tests cover unset, empty, boolean, interval, and timestamp rendering.

### Task 3: Add Shared Detail Overrides, Enrichment, and Zeek Value Derivation

Status: complete.

- YAML-authored source-neutral shared-detail overrides are supported and validated.
- Omitted network, DNS, and HTTP context values are deterministically enriched on expanded source-neutral events
  before output writers run.
- Deterministic Zeek-owned values remain in the writer path, including UIDs, connection state, history, status
  messages, and HTTP transaction depth.

Goal: let authors provide low-level shared details when they need exact control, then fill missing details
deterministically during Zeek generation without pushing Zeek-specific fields into source-neutral events.

Implemented:

- Add optional authored shared-detail fields for flow, DNS, and HTTP context. Keep these under source-neutral namespaces
  such as `network`, `dns`, or `http`, not a Zeek namespace.
- Define the YAML shape for those details on supported authored events. The supported shared-detail fields are:

| Namespace | Fields |
| --- | --- |
| `network` | `source_port`, `orig_bytes`, `resp_bytes`, `orig_pkts`, `resp_pkts` |
| `dns` | `trans_id`, `rtt`, `ttls`, `flags` |
| `http` | `user_agent`, `version`, `response_body_len`, `response_content_type` |

- Add source-neutral model fields to carry those shared details after YAML parsing and event expansion.
- Add validation that authored shared details are plausible, for example source ports are in range and packet or byte
  counts are non-negative.
- Apply precedence rules where authored shared details win and deterministic shared enrichment fills omitted details.
- Use deterministic logical flow keys during enrichment and retain Zeek-specific UIDs in the Zeek writer.
- Preserve stable client source port derivation per flow when the author omits a port.
- Honor authored byte or packet counts and derive omitted estimates in source-neutral enrichment.
- Honor authored DNS transaction IDs, response intervals, answer TTLs, and flags, with deterministic enrichment defaults.
- Honor authored HTTP user agent, HTTP version, response size, and MIME hints, with deterministic enrichment defaults.
- Keep Zeek-owned values such as `uid`, connection state, history, and TSV rendering details inside
  `log_generator.output.zeek`.
- Keep Zeek HTTP transaction depth calculation for multiple requests sharing one connection.
- Keep status message derivation for common HTTP status codes used by canonical scenarios.

Acceptance criteria:

- Re-running the same scenario with the same seed produces byte-for-byte identical Zeek records, except deterministic
  header times when tests intentionally vary `generated_at`.
- Authored source port, byte count, packet count, DNS transaction, HTTP user-agent, or response-size values appear in
  Zeek output instead of generated defaults.
- Zeek `conn.log`, `dns.log`, and `http.log` consume the same shared client source port for a flow.
- Shared authored and generated contexts can be consumed by future writers without depending on Zeek output objects.
- The first misuse HTTP request has transaction depth `1`.
- The second misuse HTTP request reuses the same HTTP connection `uid` and has transaction depth `2`.
- DNS and HTTP records share the same `uid` as their underlying `conn.log` records.

### Task 4: Build Source-Neutral to Zeek Record Mapping

Status: complete.

Goal: convert expanded source-neutral events into Zeek stream records using existing event facts and environment
visibility.

Implemented:

- DNS mapping from `dns_lookup` events to `dns.log` and a sibling UDP `conn.log` record.
- HTTP mapping from `web_request` events to `http.log` and a sibling TCP `conn.log` record.
- Connection mapping from `network_connection` events to `conn.log` records.
- De-duplication so one source-neutral `network_connection` produces one Zeek `conn.log` record.
- Sensor visibility filtering for `zeek-sensor-01`.
- Ignoring local host-only events such as `linux_local_login`.

Acceptance criteria:

- Benign canonical Zeek output contains one DNS `conn.log` row, one HTTP `conn.log` row, one `dns.log` row, and one
  `http.log` row.
- Misuse canonical Zeek output contains one DNS `conn.log` row, one HTTP `conn.log` row, one `dns.log` row, and two
  `http.log` rows.
- Login events do not produce Zeek rows.
- Records are ordered by Zeek timestamp, then deterministic sequence order.

### Task 5: Write Zeek Files Under the Output Contract

Status: complete.

Goal: write Zeek output into the existing source-first directory layout.

Implemented:

- `logs/zeek-sensor-01/zeek/conn.log`
- `logs/zeek-sensor-01/zeek/dns.log`
- `logs/zeek-sensor-01/zeek/http.log`
- No empty files for zero-record streams.
- Safe path handling through the existing output path validation helpers.
- A public function such as `write_zeek_logs(output_root, scenarios, generated_at=None)`.

Acceptance criteria:

- Zeek files are created only when `zeek` is requested and matching records exist.
- Generic normalized JSONL remains available when `generic-normalized` is requested.
- No `logs/zeek-sensor-01` directory is created when Zeek is not requested.
- Paths match `docs/output-contract-draft.md`.

### Task 6: Extend Manifest Generation

Status: complete.

Goal: describe generated Zeek files without requiring consumers to inspect the payloads.

Implemented:

- File entries for each written Zeek stream.
- `source_id: zeek-sensor-01`, `source_kind: sensor`, `log_family: zeek`, and `format: zeek-tsv`.
- `timestamp_fields: ["ts"]` for Zeek stream entries.
- `scenario_ids` and relevant source-neutral `event_types` per stream.
- `omitted_streams` entries for requested Zeek streams with zero records when useful.

Acceptance criteria:

- A Zeek-enabled canonical run lists generic and Zeek files in the top-level manifest.
- Record counts in manifest entries match non-header Zeek rows.
- `requested_output_families` includes `zeek` when requested.
- Existing generic-only manifest tests still pass.

### Task 7: Integrate Run API and CLI Output Selection

Status: complete.

Goal: keep the user-facing run path unchanged while honoring requested output families.

Implemented:

- Dispatch output writers from `Scenario.output_families` through `src/log_generator/output/registry.py`.
- Ensure unsupported requested families fail before partial output is written.
- Preserve `--run-id` and `--generated-at` reproducibility.
- Keep CLI errors concise for expected validation mistakes.

Acceptance criteria:

- `log-generator generate --scenario <zeek-yaml> --output <dir>` writes the requested output families.
- Generic-only scenarios keep their current output tree.
- Zeek-enabled scenarios write both generic and Zeek output when both families are requested.
- CLI tests assert generated Zeek paths and manifest entries.

### Task 8: Add Documentation and Examples

Status: complete.

Goal: make source-specific output discoverable without promising broader log-family support.

Implemented:

- README example showing `output_families: [generic-normalized, zeek]`.
- README output tree example including `conn.log`, `dns.log`, and `http.log`.
- Notes that Zeek TSV targets core Zeek 8.2.x-compatible fields.
- Notes that `files.log`, `ssl.log`, `x509.log`, Apache, auditd, firewall, and proxy output remain future work.

Acceptance criteria:

- Documentation examples match executable behavior.
- Documentation does not imply SIEM ingestion configuration is generated.
- Documentation states that local login events do not produce Zeek network records.

## Milestone Status

### Milestone 1: Output-Family Gate and Zeek Rendering Primitives

Status: complete. Tasks 1, 2, and 3 are complete.

Includes tasks 1 through 3.

Exit criteria:

- Zeek can be requested by YAML.
- Zeek schemas, TSV headers, value rendering, and deterministic helper derivation are tested.
- Unsupported source-specific families continue to fail explicitly.

### Milestone 2: Canonical Zeek Record Generation

Status: complete.

Includes tasks 4 and 5.

Exit criteria:

- Canonical source-neutral DNS and HTTP events produce Zeek `conn.log`, `dns.log`, and `http.log`.
- Zeek output paths match the output contract.
- Generic-only runs continue to write normalized JSONL at the same path; shared context defaults are now populated
  there as well.

### Milestone 3: Manifest, CLI, and Documentation

Status: complete.

Includes tasks 6 through 8.

Exit criteria:

- Manifest entries describe all generated Zeek files.
- CLI runs Zeek-enabled scenarios end to end.
- README shows the Zeek workflow and the remaining source-specific limitations.

## Testing Plan

Required test groups:

- YAML validation tests for supported and unsupported output families.
- Unit tests for Zeek timestamp, scalar, set, vector, and header rendering.
- Unit tests for authored shared-detail overrides, deterministic shared flow, DNS, and HTTP context, plus Zeek `uid`
  derivation.
- Canonical benign Zeek output tests.
- Canonical misuse Zeek output tests.
- Manifest tests for generic-only and generic-plus-Zeek output.
- CLI tests for Zeek-enabled generation.

Recommended exact assertions:

- Benign Zeek run writes `conn.log`, `dns.log`, and `http.log`.
- Benign `conn.log` has two data rows: one DNS flow and one HTTP flow.
- Benign `dns.log` has one data row for `web-server-01.internal`.
- Benign `http.log` has one data row for `GET /` with status `200`.
- Misuse `http.log` has two rows with transaction depths `1` and `2`.
- Misuse archive request includes filename or MIME hints only when those fields are part of the selected MVP schema.
- DNS and HTTP stream `uid` values match corresponding `conn.log` rows.
- `linux_local_login` produces no Zeek rows.
- Existing tests for generic output and Phase 2 YAML loading still pass.

Repository checks for this checkout:

```bash
uv lock --check
uv run --frozen pytest
uv run --frozen flake8 src tests
```

## Resolved Phase 3 Questions

These decisions incorporate the answered Phase 3 planning questions:

1. Keep Zeek output as native TSV only for now. Do not add Zeek JSONL.
2. Keep both Zeek version targets: core fields should stay compatible with Zeek 8.2.x and Zeek 8.0.x LTS.
3. Allow scenarios to request both `generic-normalized` and `zeek`. This means one run can write the existing
   source-neutral JSONL output and the new Zeek TSV files side by side.
4. Allow Zeek-only runs. This means `output_families: [zeek]` should write only Zeek files and should not force
   `logs/source-neutral-core/generic-normalized/events.jsonl` to exist.
5. Do not create empty Zeek log files for streams with zero records.
6. Derive Zeek header times from `generated_at` when it is provided.
7. Use only `zeek-sensor-01` as the Phase 3 Zeek sensor. This keeps sensor selection scoped to `linux-mini-lab`
   instead of adding multi-sensor routing.
8. Reuse the same HTTP connection when multiple HTTP requests belong to the same scenario, source host, service,
   correlation, and destination. This is what gives the canonical misuse sequence transaction depths `1` and `2`
   on one shared Zeek connection UID.
9. Keep authored flow facts source-neutral and prefer authored values. Shared enrichment fills omissions before
   output-family writers run, so generic JSONL and Zeek receive the same generated context.

| Decision | Resolved Behavior | Reason |
| --- | --- | --- |
| Zeek format | Native TSV only | Matches Zeek defaults and avoids duplicating generic JSONL. |
| Zeek version target | Core fields compatible with Zeek 8.2.x and 8.0.x LTS | Matches the schema notes and reduces field churn. |
| `generic-normalized` with Zeek | Allow both; default remains generic-only | Keeps family selection and output layout stable while enabling source-specific output explicitly. |
| Zeek-only runs | Allow if `zeek` is the only requested family | Output families should describe what to write, not force generic output. |
| Empty streams | Do not create files; record omitted streams when useful | Matches the output contract and avoids misleading empty logs. |
| Header times | Derive from `generated_at` when available | Keeps test output reproducible. |
| Sensor selection | Use `zeek-sensor-01` only | Keeps Phase 3 scoped to `linux-mini-lab`. |
| HTTP connection reuse | Reuse connection by scenario, source host, service, correlation, and destination | Supports the canonical misuse two-request sequence. |
| Shared flow facts | Authored values win; source-neutral enrichment fills omissions | Gives users exact control and keeps generated facts consistent across output families. |

## Current Implementation Status

The Phase 3 delivery is complete. Tasks 1 through 8 and Milestones 1 through 3 are complete. Task 3 adds a shared
source-neutral enrichment pass in `src/log_generator/core/enrichment.py`; the output manifest applies it before
dispatching writers, and direct Zeek record callers use the same pass.

The implemented Phase 3 boundary remains intentionally narrow: only `zeek` is supported as a source-specific output
family, only the `linux-mini-lab` environment is accepted by the Zeek writer, and only `conn.log`, `dns.log`, and
`http.log` are emitted. The Phase 4 plan covers `files.log`, `ssl.log`, and `x509.log`; Apache, auditd, firewall, and
proxy remain later work.

## Risks and Mitigations

| Risk | Impact | Mitigation |
| --- | --- | --- |
| Zeek fields leak into source-neutral events | Core model becomes source-specific | Keep all Zeek derivation in `log_generator.output.zeek`. |
| Shared flow facts drift between output families | Later writers disagree with generic JSONL and Zeek records | Keep enrichment before writer dispatch and reuse the enriched scenario in each writer. |
| Authored low-level details are invalid | Generated logs become impossible or contradictory | Validate authored shared details before enrichment and fail with field-path errors. |
| Generated `uid` relationships drift between streams | Zeek files become internally inconsistent | Test DNS and HTTP `uid` linkage against `conn.log`. |
| Byte and packet counts look arbitrary | Output is less useful for analysts | Use deterministic, documented heuristics based on method, status, and route class. |
| Manifest changes break generic-only output | Existing users regress | Preserve current generic-only tests and add mixed-family tests. |
| Source-specific validation becomes too broad | Phase 3 slips into later phases | Support only Zeek, only `linux-mini-lab`, and only `conn`, `dns`, and `http`. |
| Zeek schemas overfit current docs | Later Zeek versions require churn | Keep field definitions centralized and limited to core common fields. |

## Phase 3 Completion Criteria

Phase 3 is complete. The implemented criteria are:

- YAML and Python scenarios can request `zeek`.
- Zeek TSV `conn.log`, `dns.log`, and `http.log` are generated for canonical web scenarios.
- Zeek records use deterministic headers, ordering, IDs, ports, durations, counts, DNS details, and HTTP details.
- DNS and HTTP records share `uid` values with their underlying `conn.log` rows.
- Manifest entries describe every generated Zeek file; generic-only selection and output layout remain supported, with
  shared contexts now populated on normalized events.
- CLI generation works for generic-only and Zeek-enabled YAML scenarios.
- README documents the Zeek workflow and current exclusions.
- The full test suite passes.
- `uv run --frozen flake8 src tests` passes.

## Phase 4 Handoff

Phase 4 is planned to extend the Zeek writer with `files.log`, `ssl.log`, and `x509.log`. The detailed scope, dependency
order, model work, milestones, and acceptance criteria are in `docs/phase-4-planning.md`.

The phase keeps one Zeek output family and reuses Phase 3 flow, DNS, and HTTP context. Later phases can add other source
families after these Zeek streams and their certificate linkages are covered.
