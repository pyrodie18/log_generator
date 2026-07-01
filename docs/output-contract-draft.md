# Output Directory and Manifest Contract Draft

## Purpose

This document defines the first parser-friendly output directory contract for the synthetic log generator. It is scoped
to Phase 0 planning and should let Phase 1 implement a generic normalized JSON Lines writer without guessing path,
manifest, metadata, or empty-file behavior.

The contract is intentionally SIEM-neutral. It describes generated files and their source systems, but it does not
assign index names, sourcetypes, parser configuration, normalization pipelines, dashboards, or collector settings.

## Design Goals

- Keep paths stable, filesystem-safe, and easy to inspect by hand.
- Put the generating source before the log family so related source outputs are grouped together.
- Make generic normalized JSONL the official MVP output family.
- Let manifests describe generated files without requiring consumers to inspect payloads first.
- Keep answer keys and other training metadata out of generated source logs.
- Avoid creating empty log files unless a later implementation has a concrete consumer need.

## Directory Layout

The root output directory should use this shape:

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

The `logs/` tree contains generated event or source records. The `metadata/` tree contains run, scenario, and
answer-key data that should not be treated as source telemetry.

## Path Component Rules

Every path component below `output/` must be deterministic and filesystem-safe.

| Component | Rule |
| --- | --- |
| `generating_source_id` | Environment source ID or logical writer ID that produced the file. |
| `log_family` | Output family such as `generic-normalized`, `zeek`, `apache`, `auditd`, or `firewall`. |
| `log_stream` | Stream filename such as `events.jsonl`, `conn.log`, `access.log`, or `audit.log`. |

Valid path components should:

- Use lowercase ASCII letters, digits, hyphens, underscores, and dots.
- Start with a lowercase letter or digit.
- Avoid whitespace.
- Avoid path separators, shell metacharacters, drive prefixes, `.` components, and `..` components.
- Avoid changing meaning based on case; IDs should be treated as case-sensitive but authored in lowercase.

The MVP writer should reject unsafe or unknown path components during validation instead of silently rewriting them.
Rejecting bad IDs early keeps generated paths reproducible and avoids surprising manifest entries.

## Generic Normalized JSONL

The official MVP output family is generic normalized JSON Lines. It is produced by the source-neutral core rather than
by a modeled host, sensor, or network device.

Canonical location:

```text
output/
  logs/
    source-neutral-core/
      generic-normalized/
        events.jsonl
```

Rules:

- `source-neutral-core` is a logical generating source ID.
- `generic-normalized` is the log family.
- `events.jsonl` contains expanded source-neutral events, one JSON object per line.
- Records should be sorted by timestamp, then by authored or expanded event sequence order.
- Each record should include the common event envelope from `docs/event-taxonomy-draft.md`.
- Records should use timezone-aware UTC timestamps in a stable ISO 8601 representation.
- Source-specific fields such as Zeek `uid`, Apache byte counts, auditd serial numbers, and firewall rule renderings
  should not be required in this file.

The generic JSONL file is always available when a scenario successfully expands into source-neutral events. Source
specific families are optional and depend on later generator support, requested output families, and environment
visibility.

## Source-Specific Output Paths

Future source-specific generators should use the same source-first layout. For the `linux-mini-lab` template, expected
paths include:

```text
output/
  logs/
    zeek-sensor-01/
      zeek/
        conn.log
        dns.log
        http.log
    linux-ws-01/
      auditd/
        audit.log
    web-server-01/
      apache/
        access.log
        error.log
      auditd/
        audit.log
    boundary-fw-01/
      firewall/
        traffic.log
```

The source ID should identify the entity or logical writer that generated the record, not the event's origin host. For
example, a web request from `linux-ws-01` to `web-server-01` can produce Apache records under
`logs/web-server-01/apache/access.log` because `web-server-01` owns the Apache service.

## Manifest File

`output/manifest.json` is the top-level index of generated artifacts. It should describe what was written, why files
were omitted, and which scenarios contributed records.

Minimum shape:

```json
{
  "schema_version": "output-manifest/v0.1",
  "generated_at": "2026-01-15T14:00:03Z",
  "generator": {
    "name": "log-generator",
    "version": "0.1"
  },
  "run": {
    "run_id": "run-example-001",
    "seed": 1001,
    "output_root": "output"
  },
  "scenarios": [
    {
      "scenario_id": "scenario-benign-internal-web",
      "scenario_name": "Benign Internal Web Browsing",
      "environment_id": "linux-mini-lab",
      "environment_version": "0.1",
      "seed": 1001,
      "time_range": {
        "start": "2026-01-15T14:00:00Z",
        "end": "2026-01-15T14:00:10Z"
      }
    }
  ],
  "requested_output_families": [
    "generic-normalized"
  ],
  "files": [
    {
      "path": "logs/source-neutral-core/generic-normalized/events.jsonl",
      "source_id": "source-neutral-core",
      "source_kind": "logical",
      "log_family": "generic-normalized",
      "log_stream": "events.jsonl",
      "format": "jsonl",
      "record_count": 3,
      "timestamp_fields": [
        "timestamp"
      ],
      "scenario_ids": [
        "scenario-benign-internal-web"
      ],
      "event_types": [
        "dns_lookup",
        "network_connection",
        "web_request"
      ]
    }
  ],
  "metadata_files": [
    {
      "path": "metadata/scenario-manifest.json",
      "format": "json",
      "record_count": 1
    }
  ],
  "omitted_streams": []
}
```

### Manifest Fields

| Field | Required | Description |
| --- | --- | --- |
| `schema_version` | yes | Manifest schema version. MVP value is `output-manifest/v0.1`. |
| `generated_at` | yes | UTC timestamp for when the output set was written. |
| `generator` | yes | Generator name and version metadata. |
| `run` | yes | Run identifier, seed, and root path context. |
| `scenarios` | yes | Scenario IDs, names, environment references, seeds, and time ranges. |
| `requested_output_families` | yes | Output families requested by the scenario or calling code. |
| `files` | yes | Generated log files, including generic normalized JSONL and future source-specific files. |
| `metadata_files` | yes | Generated metadata files such as scenario manifests and ground truth. |
| `omitted_streams` | yes | Configured or requested streams skipped by the writer. Empty list when nothing was skipped. |

### File Entries

Each item in `files` should include:

| Field | Required | Description |
| --- | --- | --- |
| `path` | yes | Path relative to the output root. |
| `source_id` | yes | Generating source ID, such as `source-neutral-core` or `zeek-sensor-01`. |
| `source_kind` | yes | `logical`, `host`, `sensor`, `network_device`, or another documented source category. |
| `log_family` | yes | Output family name. |
| `log_stream` | yes | Stream filename. |
| `format` | yes | File format such as `jsonl`, `json`, `text`, or future `zeek-tsv`. |
| `record_count` | yes | Number of records written to the file. |
| `timestamp_fields` | yes | Payload fields that represent record time. Empty list only when the file has no timestamp field. |
| `scenario_ids` | yes | Scenarios that contributed records to the file. |
| `event_types` | no | Source-neutral event types represented in the file when known. |

The manifest may later add hashes, byte sizes, compression details, or source-native schema versions. These additions
should remain descriptive metadata, not SIEM routing instructions.

### Omitted Streams

The writer should not create empty log files for configured streams with zero records in the first implementation.
Instead, the manifest can record skipped streams when the information helps humans understand coverage.

Example:

```json
{
  "source_id": "web-server-01",
  "source_kind": "host",
  "log_family": "apache",
  "log_stream": "error.log",
  "reason": "zero_records",
  "requested": true,
  "configured": true
}
```

Recommended omitted-stream reasons:

| Reason | Meaning |
| --- | --- |
| `zero_records` | The source and stream were configured, but no generated records targeted the stream. |
| `family_not_requested` | The environment supports the stream, but the run did not request its family. |
| `unsupported_generator` | The scenario requested the family, but the writer does not implement it yet. |
| `visibility_not_applicable` | Environment visibility or routing rules did not produce records for the stream. |

`omitted_streams` should not become an error list. Validation and generation errors should be reported separately by
the caller or a future run-status artifact.

## Scenario Manifest

`metadata/scenario-manifest.json` should describe scenario-level inputs and expansion results without duplicating every
event record from `events.jsonl`.

Recommended fields:

- Scenario ID, name, seed, environment ID, and environment version.
- Authored event count and expanded event count.
- Requested output families.
- Scenario time range.
- Correlation IDs generated or referenced by the scenario.
- Answer-key labels present in the scenario, without copying hidden descriptions into source logs.

This file is useful for quick inspection, fixtures, and test assertions. The top-level `manifest.json` remains the
authoritative list of files that were written.

## Ground Truth

`metadata/ground-truth.jsonl` contains hidden answer-key records for training and evaluation. These records should
never be written into source-specific logs or generic normalized event logs.

The file should be omitted when a scenario has no answer-key records. For example, the benign internal web scenario
should not create `metadata/ground-truth.jsonl` by default.

Minimum record shape:

```json
{
  "scenario_id": "scenario-local-account-misuse-web",
  "correlation_id": "corr-local-account-misuse-001",
  "label": "suspicious_internal_web_download",
  "primary_event_id": "evt-misuse-web-005",
  "supporting_event_ids": [
    "evt-misuse-web-001",
    "evt-misuse-web-004"
  ],
  "description": "Suspicious local account use followed by admin page access and archive download."
}
```

Ground-truth records may include ATT&CK technique IDs, technique names, severity labels, or training tags when the
scenario provides them. Those fields remain metadata outputs and should not be required for benign scenarios.

## Empty File Policy

The MVP writer should create a file only when it has at least one record, except for `manifest.json`, which is always
created for a successful run.

| File | Empty Behavior |
| --- | --- |
| `manifest.json` | Always created for a successful run. |
| `logs/source-neutral-core/generic-normalized/events.jsonl` | Created when expanded source-neutral events exist. |
| Source-specific log files | Created only when generated records exist. |
| `metadata/scenario-manifest.json` | Created when scenario metadata is available for a successful run. |
| `metadata/ground-truth.jsonl` | Created only when answer-key records exist. |

This policy keeps the first output tree compact and avoids implying that a configured source produced an empty source
log. Consumers that need complete coverage can use `manifest.json` and `omitted_streams`.

## SIEM-Neutrality Rules

The manifest may include:

- Paths, formats, record counts, timestamp fields, source IDs, log families, streams, and scenario IDs.
- Source-neutral event types represented in each file.
- Environment source kinds such as `host`, `sensor`, `network_device`, and `logical`.

The manifest should not include:

- Splunk sourcetypes, indexes, props, transforms, or deployment paths.
- Elastic index templates, ECS mapping declarations, ingest pipelines, or data streams.
- QRadar log source type IDs, DSM configuration, or routing hints.
- Vendor-specific collector destinations or parser names.

This boundary keeps output generation independent from downstream ingestion decisions.

## Canonical Scenario Expectations

### Generic-Only Benign Run

When `scenario-benign-internal-web` requests only `generic-normalized`, the output tree should be:

```text
output/
  manifest.json
  logs/
    source-neutral-core/
      generic-normalized/
        events.jsonl
  metadata/
    scenario-manifest.json
```

Expected records:

- `events.jsonl` contains 3 expanded source-neutral events.
- `ground-truth.jsonl` is omitted.
- Source-specific Zeek, Apache, auditd, and firewall files are omitted because their families were not requested.

### Generic-Only Misuse Run

When `scenario-local-account-misuse-web` requests only `generic-normalized`, the output tree should include:

```text
output/
  manifest.json
  logs/
    source-neutral-core/
      generic-normalized/
        events.jsonl
  metadata/
    ground-truth.jsonl
    scenario-manifest.json
```

Expected records:

- `events.jsonl` contains 5 expanded source-neutral events.
- `ground-truth.jsonl` contains the `suspicious_internal_web_download` answer-key record.
- Source-specific files are omitted unless the run explicitly requests those families and their generators exist.

### Future Full-Family Misuse Run

When a later implementation supports and requests `generic-normalized`, `zeek`, `apache`, `auditd`, and `firewall`,
the misuse scenario can produce:

```text
output/
  manifest.json
  logs/
    source-neutral-core/
      generic-normalized/
        events.jsonl
    zeek-sensor-01/
      zeek/
        conn.log
        dns.log
        http.log
    linux-ws-01/
      auditd/
        audit.log
    web-server-01/
      apache/
        access.log
    boundary-fw-01/
      firewall/
        traffic.log
  metadata/
    ground-truth.jsonl
    scenario-manifest.json
```

`web-server-01/apache/error.log` should still be omitted when no generated records target that stream.

## Validation Targets

Phase 1 tests should be able to assert:

- Every generated file appears in `manifest.json`.
- Every manifest path uses filesystem-safe components and is relative to the output root.
- Generic normalized JSONL is written to `logs/source-neutral-core/generic-normalized/events.jsonl`.
- Manifest `record_count` values match the number of records written.
- Benign generic-only output omits `ground-truth.jsonl`.
- Misuse generic-only output includes `ground-truth.jsonl`.
- Source-specific paths can be derived from environment logging profiles without reading event payloads.
- Empty configured streams are represented through `omitted_streams` when coverage reporting is requested.

## Decisions Incorporated

- Generic normalized JSONL is the official MVP output family.
- Generic normalized JSONL uses logical source ID `source-neutral-core`.
- Output paths are source-first: source ID, log family, then stream filename.
- Empty source log files are not created in the MVP.
- `ground-truth.jsonl` is omitted when no answer-key records exist.
- The manifest describes files, formats, timestamps, source IDs, and scenario IDs, but avoids SIEM-specific routing or
  parser configuration.
