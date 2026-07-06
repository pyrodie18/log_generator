"""
End-to-end regression tests for the Phase 1 canonical scenarios.
"""

from datetime import datetime, timezone
from pathlib import Path

from log_generator.core.environment import Environment, build_linux_mini_lab
from log_generator.core.scenarios import (
    Scenario,
    build_benign_internal_web_scenario,
    build_local_account_misuse_web_scenario,
)
from log_generator.output.manifest import write_output_manifest
from support import read_json, read_jsonl


def assert_parent_links_are_earlier(scenario: Scenario) -> None:
    """
    Assert every parent reference points to an earlier ordered event.

    Args:
        scenario (Scenario): Scenario to inspect.

    Returns:
        None: This helper asserts parent linkage directly.
    """
    earlier_event_ids = set()

    for event in scenario.ordered_events():
        parent_event_id = getattr(event, "parent_event_id", None)

        if parent_event_id is not None:
            assert parent_event_id in earlier_event_ids

        earlier_event_ids.add(event.event_id)


def assert_environment_references_resolve(scenario: Scenario, environment: Environment) -> None:
    """
    Assert all canonical event references resolve through the environment.

    Args:
        scenario (Scenario): Scenario whose events should resolve.
        environment (Environment): Environment used for reference lookups.

    Returns:
        None: This helper asserts environment resolution directly.
    """
    for event in scenario.ordered_events():
        actor_user_id = getattr(event, "actor_user_id", None)
        source_host_id = getattr(event, "source_host_id", None)
        destination_host_id = getattr(event, "destination_host_id", None)
        target_host_id = getattr(event, "target_host_id", None)
        service_id = getattr(event, "service_id", None)

        if actor_user_id is not None:
            assert environment.get_user(actor_user_id) is not None

        if source_host_id is not None:
            assert environment.get_host(source_host_id) is not None

        if destination_host_id is not None:
            assert environment.get_host(destination_host_id) is not None

        if target_host_id is not None:
            assert environment.get_host(target_host_id) is not None

        if service_id is not None:
            assert environment.get_service(service_id) is not None

        if event.event_type == "dns_lookup":
            assert environment.get_dns_record(event.query_name, event.query_type) is not None

        if event.event_type == "web_request":
            assert environment.get_http_route(event.service_id, event.method, event.path) is not None


def test_canonical_environment_references_resolve_through_linux_mini_lab() -> None:
    """
    Verify every canonical scenario reference resolves through linux-mini-lab.

    Returns:
        None: This test asserts environment lookups directly.
    """
    environment = build_linux_mini_lab()

    assert_environment_references_resolve(build_benign_internal_web_scenario(), environment)
    assert_environment_references_resolve(build_local_account_misuse_web_scenario(), environment)


def test_benign_canonical_sequence_matches_documented_fixture() -> None:
    """
    Verify the benign canonical scenario's exact event sequence.

    Returns:
        None: This test asserts exact IDs, timestamps, correlation, and parent links.
    """
    scenario = build_benign_internal_web_scenario()
    records = [event.to_dict() for event in scenario.ordered_events()]

    assert len(records) == 3
    assert [(record["event_id"], record["event_type"], record["timestamp"]) for record in records] == [
        ("evt-benign-web-001", "dns_lookup", "2026-01-15T14:00:00+00:00"),
        ("evt-benign-web-002", "network_connection", "2026-01-15T14:00:01+00:00"),
        ("evt-benign-web-003", "web_request", "2026-01-15T14:00:02+00:00"),
    ]
    assert {record["correlation_id"] for record in records} == {"corr-benign-internal-web-001"}
    assert "parent_event_id" not in records[0]
    assert records[1]["parent_event_id"] == "evt-benign-web-001"
    assert records[2]["parent_event_id"] == "evt-benign-web-002"
    assert records[2]["url"] == "http://web-server-01.internal/"
    assert records[2]["status_code"] == 200
    assert_parent_links_are_earlier(scenario)


def test_misuse_canonical_sequence_matches_documented_fixture() -> None:
    """
    Verify the misuse canonical scenario's exact event sequence and metadata.

    Returns:
        None: This test asserts exact IDs, timestamps, ATT&CK metadata, and download metadata.
    """
    scenario = build_local_account_misuse_web_scenario()
    records = [event.to_dict() for event in scenario.ordered_events()]

    assert len(records) == 5
    assert [(record["event_id"], record["event_type"], record["timestamp"]) for record in records] == [
        ("evt-misuse-web-001", "linux_local_login", "2026-01-15T03:12:00+00:00"),
        ("evt-misuse-web-002", "dns_lookup", "2026-01-15T03:12:15+00:00"),
        ("evt-misuse-web-003", "network_connection", "2026-01-15T03:12:16+00:00"),
        ("evt-misuse-web-004", "web_request", "2026-01-15T03:12:18+00:00"),
        ("evt-misuse-web-005", "web_request", "2026-01-15T03:12:28+00:00"),
    ]
    assert {record["correlation_id"] for record in records} == {"corr-local-account-misuse-001"}
    assert records[1]["parent_event_id"] == "evt-misuse-web-001"
    assert records[2]["parent_event_id"] == "evt-misuse-web-002"
    assert records[3]["parent_event_id"] == "evt-misuse-web-003"
    assert records[4]["parent_event_id"] == "evt-misuse-web-003"
    assert records[3]["attack"] == {"technique_id": "T1087", "technique_name": "Account Discovery"}
    assert records[4]["attack"] == {"technique_id": "T1105", "technique_name": "Ingress Tool Transfer"}
    assert records[4]["metadata"] == {
        "download_classification": "download",
        "file_name": "archive.tar.gz",
    }
    assert_parent_links_are_earlier(scenario)


def test_canonical_output_contract_paths_and_record_counts(tmp_path: Path) -> None:
    """
    Verify canonical output paths, record counts, scenario IDs, and ground-truth behavior.

    Args:
        tmp_path (Path): Pytest temporary output directory.

    Returns:
        None: This test asserts generated output artifacts directly.
    """
    benign_root = tmp_path / "benign"
    misuse_root = tmp_path / "misuse"
    benign_scenario = build_benign_internal_web_scenario()
    misuse_scenario = build_local_account_misuse_web_scenario()

    benign_manifest_path = write_output_manifest(
        benign_root,
        (benign_scenario,),
        "run-benign-canonical",
        generated_at=datetime(2026, 1, 15, 14, 0, 3, tzinfo=timezone.utc),
    )
    misuse_manifest_path = write_output_manifest(
        misuse_root,
        (misuse_scenario,),
        "run-misuse-canonical",
        generated_at=datetime(2026, 1, 15, 3, 12, 29, tzinfo=timezone.utc),
    )
    benign_manifest = read_json(benign_manifest_path)
    misuse_manifest = read_json(misuse_manifest_path)
    benign_events = read_jsonl(benign_root / "logs" / "source-neutral-core" / "generic-normalized" / "events.jsonl")
    misuse_events = read_jsonl(misuse_root / "logs" / "source-neutral-core" / "generic-normalized" / "events.jsonl")

    assert benign_manifest["files"][0]["path"] == "logs/source-neutral-core/generic-normalized/events.jsonl"
    assert benign_manifest["files"][0]["record_count"] == 3
    assert benign_manifest["files"][0]["scenario_ids"] == ["scenario-benign-internal-web"]
    assert benign_manifest["metadata_files"] == [
        {"path": "metadata/scenario-manifest.json", "format": "json", "record_count": 1}
    ]
    assert len(benign_events) == 3
    assert not (benign_root / "metadata" / "ground-truth.jsonl").exists()

    assert misuse_manifest["files"][0]["path"] == "logs/source-neutral-core/generic-normalized/events.jsonl"
    assert misuse_manifest["files"][0]["record_count"] == 5
    assert misuse_manifest["files"][0]["scenario_ids"] == ["scenario-local-account-misuse-web"]
    assert misuse_manifest["metadata_files"][1]["path"] == "metadata/ground-truth.jsonl"
    assert misuse_manifest["metadata_files"][1]["record_count"] == 1
    assert len(misuse_events) == 5
    assert read_jsonl(misuse_root / "metadata" / "ground-truth.jsonl")[0]["label"] == (
        "suspicious_internal_web_download"
    )
