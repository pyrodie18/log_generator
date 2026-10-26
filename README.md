# log_generator

`log_generator` creates deterministic source-neutral log datasets from Python fixtures or YAML scenario files.

The built-in canonical data lives in YAML files:

- Environment template: `environments/linux-mini-lab.yaml`
- Scenario examples: `scenarios/canonical/benign-internal-web.yaml`
- Scenario examples: `scenarios/canonical/local-account-misuse-web.yaml`

## YAML Scenario Generation

Set up the repository-local environment with uv before using the command-line entry point:

```bash
uv sync --frozen --group dev
```

Generate the benign canonical scenario:

```bash
uv run --frozen log-generator generate \
  --scenario scenarios/canonical/benign-internal-web.yaml \
  --output output/benign
```

Generate the local account misuse scenario, including ground-truth metadata:

```bash
uv run --frozen log-generator generate \
  --scenario scenarios/canonical/local-account-misuse-web.yaml \
  --output output/local-account-misuse
```

The command writes a complete generic output tree under the requested output directory:

```text
output/benign/
  manifest.json
  logs/source-neutral-core/generic-normalized/events.jsonl
  metadata/scenario-manifest.json
```

Scenarios with answer-key records also include:

```text
metadata/ground-truth.jsonl
```

To also generate native-style Zeek TSV for visible DNS and HTTP traffic, copy or edit a scenario so
`output_families` requests both supported families:

```yaml
output_families: [generic-normalized, zeek]
```

The expanded form is equivalent:

```yaml
output_families:
  - generic-normalized
  - zeek
```

With that setting, the run writes generic JSONL plus Zeek TSV files under the source-specific sensor path:

```text
output/benign/
  manifest.json
  logs/source-neutral-core/generic-normalized/events.jsonl
  logs/zeek-sensor-01/zeek/conn.log
  logs/zeek-sensor-01/zeek/dns.log
  logs/zeek-sensor-01/zeek/http.log
  metadata/scenario-manifest.json
```

Zeek-only scenarios are also supported with `output_families: [zeek]`. In that mode the generic normalized JSONL file is
not written. Empty Zeek streams are reported in `manifest.json` with `omitted_streams` entries, and no empty log files
are created.

Use `--run-id` to set an explicit manifest run ID and `--generated-at` with a timezone-aware ISO 8601 timestamp for
reproducible examples:

```bash
uv run --frozen log-generator generate \
  --scenario scenarios/canonical/benign-internal-web.yaml \
  --output output/benign \
  --run-id run-benign-example \
  --generated-at 2026-01-15T14:00:03Z
```

Validation happens before output is written. Expected authoring errors are reported as concise `error:` messages with
the scenario ID, field path, invalid value, and reason.

Phase 3 Zeek output targets core Zeek 8.2.x-compatible TSV fields, kept compatible with Zeek 8.0.x LTS, for
`conn.log`, `dns.log`, and `http.log` in the `linux-mini-lab` environment. Local host-only events, such as local Linux
login activity, do not produce Zeek network records. Phase 4 plans to add Zeek `files.log`, `ssl.log`, and `x509.log`;
Apache, auditd, firewall, and proxy remain later work. SIEM ingestion, parser configuration, collector setup, and
dashboard configuration are not generated.

## Development

Sync the locked runtime and development dependencies into `.venv/`:

```bash
uv sync --frozen --group dev
```

Verify the lock, then run tests and lint checks:

```bash
uv lock --check
uv run --frozen pytest
uv run --frozen flake8 src tests
```

Add dependencies with `uv add` (or `uv add --group dev` for development tools). Keep generated datasets under
`output/`; they are ignored by Git.

Build release artifacts and inspect their contents before publishing:

```bash
uv build
tar -tf dist/log_generator-*.tar.gz
unzip -l dist/log_generator-*.whl
```

CI runs the lock, tests, and lint checks on Python 3.9 and 3.12, and builds release artifacts on Python 3.12.

## Project Status

Phases 0 through 3 are complete. The current implementation supports generic normalized JSONL and Zeek TSV for
`conn.log`, `dns.log`, and `http.log`. Phase 4 is planned, but has not started; it will add Zeek `files.log`, `ssl.log`,
and `x509.log` support. See the [Phase 4 plan](docs/phase-4-planning.md).

- [Architecture and roadmap](docs/synthetic-log-generator-architecture.md)
- [Phase 3 implementation and Phase 4 handoff](docs/phase-3-planning.md#current-implementation-status)
- [Detailed Phase 4 plan](docs/phase-4-planning.md)
- [YAML scenario reference](docs/scenario-yaml-schema-draft.md)
- [Output directory and manifest contract](docs/output-contract-draft.md)
