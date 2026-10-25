# Phase 2 Planning

Status: complete for deterministic single-scenario YAML files. This document records the Phase 2 scope and decisions;
source-specific exclusions below applied to that phase. Phase 3 subsequently added Zeek output. See
`docs/phase-3-planning.md` for the current handoff.

## Purpose

Phase 2 turns the Phase 1 source-neutral core into an author-facing scenario workflow. The main outcome is that a user
can write one deterministic YAML scenario file, load it through the library or command line, validate it against
`linux-mini-lab`, expand it into source-neutral events, and write the same generic normalized output contract that
Phase 1 already supports.

Phase 2 should stay focused on scenario authoring and run orchestration. It should not combine YAML loading with the
first source-specific generator unless the YAML path is already complete and stable.

## Primary Inputs

- `docs/phase-1-task-breakdown.md`
- `docs/scenario-yaml-schema-draft.md`
- `docs/output-contract-draft.md`
- `docs/canonical-scenarios.md`
- `docs/linux-mini-lab-template.md`
- `docs/event-taxonomy-draft.md`
- Existing Phase 1 modules under `src/log_generator/core/` and `src/log_generator/output/`

## Phase 2 Scope

Phase 2 includes:

- A YAML scenario loader for one scenario document per file.
- Structural validation for supported YAML fields.
- Timestamp and duration parsing for absolute timestamps, offsets from scenario start, and simple `after` plus
  `delay` dependencies.
- Mapping YAML `web_request` and `linux_local_login` authored events into existing Phase 1 scenario primitives.
- Support for optional `attack_chain` and `answer_key` metadata.
- Deterministic helper IDs, correlation IDs, parent links, and event ordering compatible with canonical fixtures.
- A public Python API for loading, validating, expanding, and writing a scenario from YAML.
- A small command-line entry point for generating an output directory from a YAML file.
- YAML fixture files for the two canonical scenarios.
- Tests that prove YAML-generated canonical output matches the Phase 1 Python fixtures.

Phase 2 excludes:

- Zeek, Apache, auditd, or firewall source-specific record generation.
- Noise profiles and random background activity.
- Multiple scenarios in one YAML file.
- Batch run orchestration across many YAML files.
- New source-neutral event types beyond the Phase 1 four-event set.
- Windows, Active Directory, cloud, proxy, TLS, process execution, or file-download event modeling.
- Stable plugin API guarantees.
- SIEM parser, collector, index, dashboard, or pipeline configuration.

## Phase 2 Deliverables

Expected files or modules:

- `src/log_generator/scenario_yaml/` (the loader was subsequently split into a package)
- `src/log_generator/cli.py`
- `scenarios/canonical/benign-internal-web.yaml`
- `scenarios/canonical/local-account-misuse-web.yaml`
- `tests/test_scenario_yaml.py`
- `tests/test_cli.py`
- README usage notes for the YAML and CLI workflow

The exact module path can follow the implementation's package organization. If an `io` package is introduced, keep it
small and limited to external representation loading rather than domain modeling.

## Recommended Implementation Order

### Task 1: Add YAML Parsing Dependency and Loader Boundary

Goal: create a small boundary that reads YAML safely without leaking parser-specific behavior through the domain model.

Implement:

- Add a YAML dependency, preferably `PyYAML`, to project metadata.
- Use safe loading only.
- Reject empty files and multi-document files in Phase 2.
- Return a plain parsed mapping to a second validation and conversion step.
- Keep file reading separate from dictionary conversion so tests can exercise both paths.

Acceptance criteria:

- `load_scenario_yaml(path)` reads a single YAML document from disk.
- `parse_scenario_yaml_text(text)` supports direct fixture tests without filesystem setup.
- Empty documents produce a clear validation error.
- Multi-document YAML produces a clear "not supported yet" error.
- No source-specific fields are accepted as first-class YAML concepts.

### Task 2: Define Structured YAML Validation Errors

Goal: make authoring mistakes easy to fix and keep validation behavior consistent with Phase 1 semantic errors.

Implement:

- A lightweight `ScenarioYamlError` or validation result object.
- Error messages that include scenario ID when available.
- Field paths such as `events[0].actor`, `time_range.start`, and `answer_key[0].primary_event_id`.
- Invalid values where useful.
- Actionable reasons that match the examples in `docs/scenario-yaml-schema-draft.md`.

Acceptance criteria:

- Missing required top-level fields are reported with field paths.
- Unknown top-level fields are rejected.
- Unknown event fields are errors by default.
- Duplicate event IDs are rejected.
- Unsafe IDs are rejected using the output path component rules where applicable.
- Tests cover representative structural errors before environment lookup begins.

### Task 3: Implement Schema Version, Environment, and Time Range Handling

Goal: convert the top-level YAML document into the metadata needed by the existing `Scenario` model.

Implement:

- Required `schema_version` with supported value `scenario/v0.1`.
- Required `id`, `name`, `seed`, `environment`, `time_range`, and `events`.
- Environment shorthand:
  - `environment: linux-mini-lab`
  - `environment: {id: linux-mini-lab, version: "0.1"}`
- UTC-aware ISO 8601 timestamp parsing, including `Z`.
- Rejection of naive timestamps.
- Optional `time_range.end`.
- Default `output_families` to `generic-normalized`.

Acceptance criteria:

- Canonical YAML examples load with exact scenario IDs, names, seeds, environment IDs, versions, and times.
- Unsupported schema versions fail before scenario expansion.
- Unknown environments fail with an actionable error.
- Missing `time_range.start` fails.
- Naive timestamp values fail.
- `output_families` defaults exactly to `("generic-normalized",)` when omitted.

### Task 4: Parse Durations and Event Timing

Goal: support the authoring-time timing forms promised by the YAML schema draft.

Implement:

- Absolute event timestamps.
- Relative `at` offsets from `time_range.start`.
- `after` references to earlier authored events.
- `delay` values used with `after`.
- Simple duration units: `ms`, `s`, `m`, and `h`.
- Rejection of compound durations such as `1m30s` unless a parser is intentionally added.

Timing rules:

- Every authored event must include `at` or `after`.
- If `at` and `after` are both present, use `at` as authoritative and keep `after` only for lineage.
- `delay` may appear only with `after`.
- `after` must reference an earlier authored event in the YAML list.
- Generated helper timestamps must not sort after the authored event they support.
- Generated helper timestamps must remain within `time_range` when `end` is provided.

Acceptance criteria:

- `at: +2s` resolves from scenario start.
- `after: evt-login` plus `delay: 18s` resolves from the referenced authored event timestamp.
- `+500ms`, `+2m`, and `+1h` parse predictably.
- Bad duration strings identify the offending field.
- Dependency cycles are impossible because forward references are rejected.

### Task 5: Convert Authored Events Into Phase 1 Primitives

Goal: reuse Phase 1 expansion behavior rather than creating a parallel YAML-specific event engine.

Implement:

- `web_request` conversion into `AuthoredWebRequest`.
- `linux_local_login` conversion into `LinuxLocalLoginEvent`.
- Field aliases exactly as documented:
  - YAML `actor` maps to `actor_user_id`.
  - YAML `source_host` maps to `source_host_id`.
  - YAML `target_host` maps to `target_host_id`.
  - YAML `service` maps to `service_id`.
- Optional `status`, `status_code`, `metadata`, and `attack`.
- Deterministic correlation IDs when omitted.
- Deterministic helper ID behavior compatible with canonical expected events.

Important decision:

The Phase 1 canonical helper IDs are fixed for tests. Phase 2 should either derive those same helper IDs from YAML
inputs or add a small, documented helper ID override mechanism. Deriving the same IDs is preferred because it keeps
YAML concise.

Acceptance criteria:

- Canonical benign YAML expands to the same three event IDs, timestamps, parent links, and serialized records as
  `build_benign_internal_web_scenario()`.
- Canonical misuse YAML expands to the same five event IDs, timestamps, parent links, attack metadata, download
  metadata, and answer-key records as `build_local_account_misuse_web_scenario()`.
- `web_request` route defaults are resolved through the environment.
- Unknown event types fail with a clear "unsupported event type" error.

### Task 6: Add Environment-Aware Validation

Goal: catch impossible YAML references before output is written.

Implement validation for:

- Unknown users, hosts, services, DNS records, and routes.
- Invalid local login hosts.
- Web requests to non-HTTP services.
- Invalid source or destination host references.
- Unsupported statuses.
- `status_code` outside 100 through 599.
- Paths that do not start with `/`.
- Bad ATT&CK technique ID format for the supported simple `T1234` form.
- Unsupported `noise_profiles` with an explicit "not supported yet" error.

Acceptance criteria:

- The two canonical YAML scenarios validate successfully.
- Tests cover unknown user, unknown host, unknown service, invalid login host, missing timestamp, bad dependency,
  unknown event field, bad route, unsupported noise profile, and invalid path.
- Errors include scenario ID, field path, invalid value, and actionable reason where applicable.

### Task 7: Support Attack Chain and Answer Key Metadata

Goal: preserve training metadata without allowing it to leak into generated source-neutral logs.

Implement:

- Optional `attack_chain` parsing and reference validation.
- Optional `answer_key` parsing into existing `AnswerKeyRecord` objects.
- Validation that primary and supporting event references resolve to authored or expanded event IDs.
- Preservation of answer-key labels and descriptions only in metadata output.

Acceptance criteria:

- Misuse canonical YAML writes `metadata/ground-truth.jsonl` with the documented label.
- Benign canonical YAML omits `metadata/ground-truth.jsonl`.
- Answer-key references to unknown events fail before writing output.
- Attack-chain metadata is available for future metadata expansion but is not required for benign scenarios.

### Task 8: Add Scenario Run API

Goal: provide a stable library entry point for callers that do not want to use the CLI.

Implement:

- A function such as `load_scenario_from_yaml(path, environment_registry=None) -> Scenario`.
- A function such as `generate_from_yaml(path, output_root, run_id=None, generated_at=None) -> Path`.
- Environment registry handling that initially knows `linux-mini-lab`.
- Optional caller-supplied `run_id`; deterministic default is acceptable if not supplied.
- Output writing through the existing `write_output_manifest` path.

Acceptance criteria:

- API callers can load a YAML scenario without writing files.
- API callers can generate a complete output tree from a YAML file.
- The API does not require CLI-specific argument parsing.
- Tests assert output manifest paths and record counts from the API.

### Task 9: Add CLI Entry Point

Goal: make the project useful from a shell while keeping command behavior small and predictable.

Implement:

- Console script such as `log-generator`.
- Command form:

```bash
uv run --frozen log-generator generate --scenario scenarios/canonical/benign-internal-web.yaml --output output/benign
```

Recommended options:

- `--scenario`: required YAML scenario path.
- `--output`: required output directory.
- `--run-id`: optional explicit run ID.
- `--generated-at`: optional deterministic timestamp for tests and reproducible examples.
- `--strict`: accepted as a reserved flag; it currently has no effect and validation errors are always strict.

Acceptance criteria:

- CLI generates the benign canonical output tree.
- CLI generates the misuse canonical output tree including ground truth.
- CLI exits non-zero on validation errors.
- CLI prints concise error messages without stack traces for expected user mistakes.
- Tests run the CLI through Python's subprocess or direct entry-point function without network access.

### Task 10: Add Canonical YAML Fixtures and Documentation

Goal: make YAML authoring reviewable and keep examples executable.

Implement:

- Canonical benign YAML fixture under `scenarios/canonical/`.
- Canonical misuse YAML fixture under `scenarios/canonical/`.
- README section showing install, generate, output paths, and validation behavior.
- A short note that source-specific Zeek, Apache, auditd, and firewall logs remain future work.

Acceptance criteria:

- Fixture YAML files match the schema draft and load through the public API.
- README commands work in a local editable install.
- Documentation does not promise source-specific output in Phase 2.

## Suggested Milestones

### Milestone 1: YAML Loader and Structural Validation

Includes tasks 1 through 4.

Exit criteria:

- YAML can be parsed safely.
- Top-level fields, schema version, environment reference, time range, event identity, and timing rules validate.
- Error messages are structured enough to be useful in tests and CLI output.

### Milestone 2: Scenario Conversion and Canonical Parity

Includes tasks 5 through 7.

Exit criteria:

- Canonical YAML scenarios expand to the same source-neutral records as Phase 1 Python fixtures.
- Environment-aware validation catches representative mistakes.
- Answer-key behavior matches the existing output contract.

### Milestone 3: Run API, CLI, and Documentation

Includes tasks 8 through 10.

Exit criteria:

- A caller can generate a full output tree from a YAML file through Python or CLI.
- CLI behavior is documented and tested.
- Phase 2 remains generic-output only.

## Testing Plan

Required test groups:

- YAML parsing and structural validation tests.
- Timestamp and duration parsing tests.
- Environment reference validation tests.
- Canonical YAML parity tests against Phase 1 Python fixtures.
- Output contract tests for YAML-generated runs.
- CLI success and failure tests.

Recommended exact assertions:

- Benign YAML expands to 3 events.
- Misuse YAML expands to 5 events.
- Event IDs, timestamps, correlation IDs, parent links, attack metadata, and download metadata match existing canonical
  tests exactly.
- Manifest record counts match generated line counts.
- Benign run omits `ground-truth.jsonl`.
- Misuse run includes one `ground-truth.jsonl` record.
- Expected validation failures report the correct field paths.

Repository checks after each implementation step:

```bash
uv lock --check
uv run --frozen pytest
uv run --frozen flake8 src tests
```

## Resolved Phase 2 Decisions

| Decision | Implemented Phase 2 Behavior | Reason |
| --- | --- | --- |
| YAML library | `PyYAML` with safe loading | Small dependency and sufficient for the draft schema. |
| Unknown top-level fields | Error in Phase 2 | Prevents typos from silently changing scenarios. |
| Unknown event fields | Error | Event typos are high impact and hard to see in generated logs. |
| Multi-document YAML | Reject | Keeps run identity and manifest behavior simple. |
| Multiple scenarios per file | Defer | Batch semantics need a separate manifest and error strategy. |
| Helper IDs | Derive canonical IDs from deterministic inputs | Keeps fixture YAML concise and avoids exposing expansion internals. |
| Omitted correlation IDs | Generate deterministic IDs | Improves author ergonomics without sacrificing reproducibility. |
| `noise_profiles` | Reject with "not supported yet" | Prevents users from assuming noise was applied. |
| Source-specific requested families | Reject explicitly in Phase 2; Phase 3 adds `zeek` | Avoids silently producing only generic output when users asked for Zeek or Apache. |

## Risks and Mitigations

| Risk | Impact | Mitigation |
| --- | --- | --- |
| YAML conversion duplicates Phase 1 expansion logic | Divergent behavior between Python and YAML scenarios | Convert YAML into existing Phase 1 primitives before expansion. |
| Error handling becomes inconsistent | CLI and tests become brittle | Centralize field-path validation errors. |
| Helper ID derivation fails canonical parity | Fixtures cannot assert exact IDs | Decide and test helper ID strategy before broad parser work. |
| YAML schema grows into a programming language | Hard to validate and explain | Keep Phase 2 to deterministic linear scenarios. |
| Source-specific output sneaks into Phase 2 | YAML work slows down and mixes concerns | Treat Zeek, Apache, auditd, and firewall families as unsupported until a later phase. |
| Dependency parsing differences affect timestamps | Non-reproducible output | Normalize all parsed datetimes through existing UTC normalization. |

## Phase 2 Completion Criteria

Phase 2 is complete. Its completion criteria were:

- The two canonical scenarios exist as YAML fixtures.
- YAML loading validates schema structure, timestamps, dependencies, references, attack metadata, and answer-key
  references.
- YAML-generated canonical scenarios match the existing Python fixture outputs exactly.
- A Python API can load and generate output from YAML.
- A CLI can generate the documented output tree from YAML.
- The full test suite passes.
- `uv run --frozen flake8 src tests` passes.

## Phase 3 Handoff

After Phase 2, the most natural next phase is the first source-specific generator. The recommended Phase 3 target is
native-style Zeek TSV output for `conn.log`, `dns.log`, and `http.log`, based on `docs/zeek-schema-notes.md`.

Phase 3 should start only after YAML can request output families explicitly and report unsupported families clearly.
That gives the Zeek generator a stable authoring and run path without requiring another scenario representation.
