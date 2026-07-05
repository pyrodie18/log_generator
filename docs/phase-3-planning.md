# Phase 3 Planning

## Purpose

Phase 3 adds the first source-specific output family: native-style Zeek TSV logs for the existing `linux-mini-lab`
canonical web scenarios. The phase should turn already-expanded source-neutral events into plausible Zeek `conn.log`,
`dns.log`, and `http.log` records while preserving the Phase 1 and Phase 2 generic normalized JSONL workflow.

This plan follows the updated architecture roadmap in `docs/synthetic-log-generator-architecture.md`. Generic
normalized JSONL, parser-friendly manifest writing, YAML loading, and CLI generation already exist, so Phase 3 should
focus on the first source-specific generator rather than replanning implemented generic output work.

## Primary Inputs

- `docs/phase-2-planning.md`
- `docs/zeek-schema-notes.md`
- `docs/output-contract-draft.md`
- `docs/canonical-scenarios.md`
- `docs/linux-mini-lab-template.md`
- Existing output modules under `src/log_generator/output/`
- Existing scenario loading and CLI workflow in `src/log_generator/scenario_yaml.py` and `src/log_generator/cli.py`

## Phase 3 Scope

Phase 3 includes:

- Support for `output_families: [generic-normalized, zeek]` in YAML and Python scenarios.
- A Zeek output package that writes native-style TSV files.
- Generation of `conn.log`, `dns.log`, and `http.log` for traffic visible to `zeek-sensor-01`.
- Author-overridable source-neutral enrichment for shared flow, DNS, and HTTP facts such as client source ports,
  normalized flow keys, byte or packet estimates, DNS transaction context, HTTP user agents, HTTP versions, and
  response sizes.
- Deterministic Zeek-owned values such as `uid`, Zeek file IDs, Zeek connection state, Zeek history, and TSV rendering
  details.
- Manifest file entries for generated Zeek files.
- Manifest omitted-stream entries when requested Zeek streams have zero records.
- Tests for canonical benign and misuse Zeek output.
- README documentation for requesting Zeek output.

Phase 3 excludes:

- `ssl.log`, `files.log`, Apache, auditd, firewall, proxy, router, Windows, Active Directory, and cloud logs.
- New source-neutral event types.
- Batch generation across multiple YAML files.
- SIEM parser, collector, index, sourcetype, dashboard, or pipeline configuration.
- Exact packet capture fidelity.
- Site-specific Zeek packages or policy-loaded columns.
- Empty log-file creation for configured streams with no records.
- Zeek JSONL output.

## Phase 3 Deliverables

Expected files or modules:

- `src/log_generator/output/zeek.py`
- `tests/test_zeek_output.py`
- Updates to `src/log_generator/output/manifest.py`
- Updates to `src/log_generator/scenario_yaml.py`
- Updates to `src/log_generator/cli.py` only if CLI output-family behavior is currently too Phase-2-specific
- Zeek-enabled YAML fixture variants or targeted test fixtures
- README usage notes for `output_families: [generic-normalized, zeek]`

The exact module layout can follow the implementation, but Zeek-specific rendering should stay outside the core
scenario and event modules. The source-neutral model should not learn Zeek field names. Shared flow facts that future
firewall, proxy, Apache, or auditd generators may also need should be accepted from authors when provided and otherwise
derived before source-specific writers run, not inside the first writer that happens to need them.

## Recommended Implementation Order

### Task 1: Accept Zeek as a Supported Output Family

Goal: let authors request Zeek output without weakening unsupported-family validation.

Implement:

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

Goal: centralize Zeek stream schemas so record rendering, tests, and manifest entries share one source of truth.

Implement:

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

Goal: let authors provide low-level shared details when they need exact control, fill missing shared details
deterministically, then generate Zeek-owned values without pushing Zeek-specific fields into source-neutral events.

Implement:

- Optional authored shared detail fields for flow, DNS, and HTTP context. Keep these under a source-neutral namespace
  such as `network`, `dns`, or `http`, not a Zeek namespace.
- Precedence rules where authored shared details win and deterministic enrichment fills only omitted details.
- Validation that authored shared details are plausible, for example source ports are in range and packet or byte
  counts are non-negative.
- Deterministic source-neutral flow keys for DNS and HTTP flows when the author omits them.
- Stable client source port derivation per flow, exposed through shared flow context when the author omits a port.
- Shared byte or packet estimates where later firewall, proxy, or host generators must agree with Zeek.
- Shared DNS response context such as transaction IDs, response intervals, answer TTLs, and flags when those values may
  be needed by future DNS server logs.
- Shared HTTP request context such as default user agent, HTTP version, response size, and MIME hints when those values
  may be needed by future Apache or proxy generators.
- Stable Zeek `uid` derivation per connection-like flow.
- Plausible deterministic Zeek connection state and history values.
- Zeek HTTP transaction depth calculation for multiple requests sharing one connection.
- Status message derivation for common HTTP status codes used by canonical scenarios.

Acceptance criteria:

- Re-running the same scenario with the same seed produces byte-for-byte identical Zeek records, except deterministic
  header times when tests intentionally vary `generated_at`.
- Authored source port, byte count, packet count, DNS transaction, HTTP user-agent, or response-size values appear in
  Zeek output instead of generated defaults.
- Zeek `conn.log`, `dns.log`, and `http.log` consume the same shared client source port for a flow.
- The shared flow context can be passed to a future firewall generator without depending on Zeek output objects.
- The first misuse HTTP request has transaction depth `1`.
- The second misuse HTTP request reuses the same HTTP connection `uid` and has transaction depth `2`.
- DNS and HTTP records share the same `uid` as their underlying `conn.log` records.

### Task 4: Build Source-Neutral to Zeek Record Mapping

Goal: convert expanded source-neutral events into Zeek stream records using existing event facts and environment
visibility.

Implement:

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

Goal: write Zeek output into the existing source-first directory layout.

Implement:

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

Goal: describe generated Zeek files without requiring consumers to inspect the payloads.

Implement:

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

Goal: keep the user-facing run path unchanged while honoring requested output families.

Implement:

- Update the existing generation path to dispatch output writers from `Scenario.output_families`.
- Ensure unsupported requested families fail before partial output is written.
- Preserve `--run-id` and `--generated-at` reproducibility.
- Keep CLI errors concise for expected validation mistakes.

Acceptance criteria:

- `log-generator generate --scenario <zeek-yaml> --output <dir>` writes the requested output families.
- Generic-only scenarios keep their current output tree.
- Zeek-enabled scenarios write both generic and Zeek output when both families are requested.
- CLI tests assert generated Zeek paths and manifest entries.

### Task 8: Add Documentation and Examples

Goal: make source-specific output discoverable without promising broader log-family support.

Implement:

- README example showing `output_families: [generic-normalized, zeek]`.
- README output tree example including `conn.log`, `dns.log`, and `http.log`.
- Notes that Zeek TSV targets core Zeek 8.2.x-compatible fields.
- Notes that `ssl.log`, `files.log`, Apache, auditd, firewall, and proxy output remain future work.

Acceptance criteria:

- Documentation examples match executable behavior.
- Documentation does not imply SIEM ingestion configuration is generated.
- Documentation states that local login events do not produce Zeek network records.

## Suggested Milestones

### Milestone 1: Output-Family Gate and Zeek Rendering Primitives

Includes tasks 1 through 3.

Exit criteria:

- Zeek can be requested by YAML.
- Zeek schemas, TSV headers, value rendering, and deterministic helper derivation are tested.
- Unsupported source-specific families continue to fail explicitly.

### Milestone 2: Canonical Zeek Record Generation

Includes tasks 4 and 5.

Exit criteria:

- Canonical source-neutral DNS and HTTP events produce Zeek `conn.log`, `dns.log`, and `http.log`.
- Zeek output paths match the output contract.
- Generic-only output behavior is unchanged.

### Milestone 3: Manifest, CLI, and Documentation

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

Repository checks after each implementation step:

```bash
python -m pytest
flake8 --max-line-length=120 .
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
9. Keep shared flow facts source-neutral: authored values should win when present, and deterministic enrichment should
   fill omissions before writers run.

| Decision | Resolved Behavior | Reason |
| --- | --- | --- |
| Zeek format | Native TSV only | Matches Zeek defaults and avoids duplicating generic JSONL. |
| Zeek version target | Core fields compatible with Zeek 8.2.x and 8.0.x LTS | Matches the schema notes and reduces field churn. |
| `generic-normalized` with Zeek | Allow both; default remains generic-only | Keeps current behavior stable while enabling source-specific output explicitly. |
| Zeek-only runs | Allow if `zeek` is the only requested family | Output families should describe what to write, not force generic output. |
| Empty streams | Do not create files; record omitted streams when useful | Matches the output contract and avoids misleading empty logs. |
| Header times | Derive from `generated_at` when available | Keeps test output reproducible. |
| Sensor selection | Use `zeek-sensor-01` only | Keeps Phase 3 scoped to `linux-mini-lab`. |
| HTTP connection reuse | Reuse connection by scenario, source host, service, correlation, and destination | Supports the canonical misuse two-request sequence. |
| Shared flow facts | Authored values win; deterministic enrichment fills omissions before writers run | Gives users exact control without sacrificing concise reproducible scenarios. |

## Risks and Mitigations

| Risk | Impact | Mitigation |
| --- | --- | --- |
| Zeek fields leak into source-neutral events | Core model becomes source-specific | Keep all Zeek derivation in `log_generator.output.zeek`. |
| Shared flow facts are generated inside Zeek | Later firewall or proxy generators disagree with Zeek records | Add a source-neutral enrichment step for ports, flow keys, and shared request facts before Zeek rendering. |
| Authored low-level details are invalid | Generated logs become impossible or contradictory | Validate authored shared details before enrichment and fail with field-path errors. |
| Generated `uid` relationships drift between streams | Zeek files become internally inconsistent | Test DNS and HTTP `uid` linkage against `conn.log`. |
| Byte and packet counts look arbitrary | Output is less useful for analysts | Use deterministic, documented heuristics based on method, status, and route class. |
| Manifest changes break generic-only output | Existing users regress | Preserve current generic-only tests and add mixed-family tests. |
| Source-specific validation becomes too broad | Phase 3 slips into later phases | Support only Zeek, only `linux-mini-lab`, and only `conn`, `dns`, and `http`. |
| Zeek schemas overfit current docs | Later Zeek versions require churn | Keep field definitions centralized and limited to core common fields. |

## Phase 3 Completion Criteria

Phase 3 is complete when:

- YAML and Python scenarios can request `zeek`.
- Zeek TSV `conn.log`, `dns.log`, and `http.log` are generated for canonical web scenarios.
- Zeek records use deterministic headers, ordering, IDs, ports, durations, counts, DNS details, and HTTP details.
- DNS and HTTP records share `uid` values with their underlying `conn.log` rows.
- Manifest entries describe every generated Zeek file and preserve generic-only behavior.
- CLI generation works for generic-only and Zeek-enabled YAML scenarios.
- README documents the Zeek workflow and current exclusions.
- The full test suite passes.
- `flake8 --max-line-length=120 .` passes.

## Phase 4 Handoff

After Phase 3, the next phase should broaden source-specific coverage without changing the source-neutral event model
unnecessarily. The most natural follow-up is either Zeek `files.log` and `ssl.log` support or the first Linux host log
generator for auditd and Apache, depending on whether the next canonical scenario emphasizes downloads, TLS web
traffic, or host activity.
