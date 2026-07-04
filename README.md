# log_generator

`log_generator` creates deterministic source-neutral log datasets from Python fixtures or YAML scenario files.

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

Phase 2 generates only the generic normalized source-neutral output. Source-specific Zeek, Apache, auditd, and firewall
logs remain future work.

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
