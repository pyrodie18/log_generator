"""
Shared test fixtures and file readers.
"""

import json
from pathlib import Path


def canonical_benign_yaml() -> str:
    """
    Build the canonical benign scenario YAML fixture text.

    Returns:
        str: Canonical benign scenario YAML.
    """
    return """
schema_version: scenario/v0.1
id: scenario-benign-internal-web
name: Benign Internal Web Browsing
description: Alice visits the internal Apache homepage from her normal workstation.
seed: 1001
environment:
  id: linux-mini-lab
  version: "0.1"
time_range:
  start: 2026-01-15T14:00:00Z
  end: 2026-01-15T14:00:02Z
output_families:
  - generic-normalized
events:
  - id: evt-benign-web-003
    type: web_request
    at: +2s
    actor: user-alice
    source_host: linux-ws-01
    service: svc-web-http
    method: GET
    path: /
    correlation_id: corr-benign-internal-web-001
"""


def canonical_misuse_yaml() -> str:
    """
    Build the canonical local account misuse scenario YAML fixture text.

    Returns:
        str: Canonical misuse scenario YAML.
    """
    return """
schema_version: scenario/v0.1
id: scenario-local-account-misuse-web
name: Local Account Misuse and Suspicious Web Access
description: Suspicious use of Alice's local account followed by admin browsing and archive download.
seed: 2002
environment:
  id: linux-mini-lab
  version: "0.1"
time_range:
  start: 2026-01-15T03:12:00Z
  end: 2026-01-15T03:12:28Z
output_families:
  - generic-normalized
events:
  - id: evt-misuse-web-001
    type: linux_local_login
    at: +0s
    actor: user-alice
    target_host: linux-ws-01
    login_method: local_console
    metadata:
      activity_classification: suspicious
    correlation_id: corr-local-account-misuse-001
  - id: evt-misuse-web-004
    type: web_request
    after: evt-misuse-web-001
    delay: 18s
    actor: user-alice
    source_host: linux-ws-01
    service: svc-web-http
    method: GET
    path: /admin
    attack:
      technique_id: T1087
      technique_name: Account Discovery
    correlation_id: corr-local-account-misuse-001
  - id: evt-misuse-web-005
    type: web_request
    after: evt-misuse-web-004
    delay: 10s
    actor: user-alice
    source_host: linux-ws-01
    service: svc-web-http
    method: GET
    path: /admin/archive.tar.gz
    attack:
      technique_id: T1105
      technique_name: Ingress Tool Transfer
    correlation_id: corr-local-account-misuse-001
attack_chain:
  - id: step-admin-access
    name: Admin page access
    primary_event_id: evt-misuse-web-004
    technique_id: T1087
    technique_name: Account Discovery
  - id: step-archive-download
    name: Archive download
    primary_event_id: evt-misuse-web-005
    supporting_event_ids:
      - evt-misuse-web-001
      - evt-misuse-web-004
    technique_id: T1105
    technique_name: Ingress Tool Transfer
answer_key:
  - label: suspicious_internal_web_download
    primary_event_id: evt-misuse-web-005
    supporting_event_ids:
      - evt-misuse-web-001
      - evt-misuse-web-004
    description: Suspicious local account use followed by admin page access and archive download.
"""


def read_json(path: Path) -> dict:
    """
    Read a JSON file from disk.

    Args:
        path (Path): JSON file to read.

    Returns:
        dict: Parsed JSON object.
    """
    return json.loads(path.read_text(encoding="utf-8"))


def read_jsonl(path: Path) -> list[dict]:
    """
    Read JSON Lines records from disk.

    Args:
        path (Path): JSON Lines file to read.

    Returns:
        list[dict]: Parsed JSON object records.
    """
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def count_zeek_data_rows(path: Path) -> int:
    """
    Count non-header rows in a Zeek TSV file.

    Args:
        path (Path): Zeek TSV file to inspect.

    Returns:
        int: Number of rendered Zeek records, excluding header and close lines.
    """
    return sum(1 for line in path.read_text(encoding="utf-8").splitlines() if not line.startswith("#"))


def read_zeek_records(path: Path) -> list[dict[str, str]]:
    """
    Read Zeek TSV data rows into dictionaries keyed by the #fields header.

    Args:
        path (Path): Zeek TSV log file to read.

    Returns:
        list[dict[str, str]]: Parsed data records.
    """
    fields = []
    records = []

    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("#fields\t"):
            fields = line.split("\t")[1:]
            continue

        if line.startswith("#"):
            continue

        records.append(dict(zip(fields, line.split("\t"))))

    return records
