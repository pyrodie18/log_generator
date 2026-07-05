# log_generator

`log_generator` creates deterministic source-neutral log datasets from Python fixtures or YAML scenario files.

The built-in canonical data lives in YAML files:

- Environment template: `environments/linux-mini-lab.yaml`
- Scenario examples: `scenarios/canonical/benign-internal-web.yaml`
- Scenario examples: `scenarios/canonical/local-account-misuse-web.yaml`

## YAML Scenario Generation

Install the package in editable mode before using the command-line entry point:

```bash
python -m pip install -e .
```

Generate the benign canonical scenario:

```bash
log-generator generate \
  --scenario scenarios/canonical/benign-internal-web.yaml \
  --output output/benign
```

Generate the local account misuse scenario, including ground-truth metadata:

```bash
log-generator generate \
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
log-generator generate \
  --scenario scenarios/canonical/benign-internal-web.yaml \
  --output output/benign \
  --run-id run-benign-example \
  --generated-at 2026-01-15T14:00:03Z
```

Validation happens before output is written. Expected authoring errors are reported as concise `error:` messages with
the scenario ID, field path, invalid value, and reason.

Phase 3 Zeek output targets core Zeek 8.2.x-compatible TSV fields, kept compatible with Zeek 8.0.x LTS, for
`conn.log`, `dns.log`, and `http.log` in the `linux-mini-lab` environment. Local host-only events, such as local Linux
login activity, do not produce Zeek network records. Zeek `ssl.log`, `files.log`, Apache, auditd, firewall, proxy, SIEM
ingestion, parser configuration, collector setup, and dashboard configuration remain future work.

## Development

Install the package in editable mode:

```bash
python -m pip install -e .
```

Run tests and lint checks:

```bash
python -m pytest
flake8 --max-line-length=120 .
```
