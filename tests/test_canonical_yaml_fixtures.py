"""
Tests for executable canonical YAML scenario fixtures.
"""

from datetime import datetime, timezone
from pathlib import Path

from log_generator.core.scenarios import (
    Scenario,
    build_benign_internal_web_scenario,
    build_local_account_misuse_web_scenario,
)
from log_generator.scenario_yaml import generate_from_yaml, load_scenario_from_yaml
from support import read_json, read_jsonl


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
BENIGN_FIXTURE_PATH = REPOSITORY_ROOT / "scenarios" / "canonical" / "benign-internal-web.yaml"
MISUSE_FIXTURE_PATH = REPOSITORY_ROOT / "scenarios" / "canonical" / "local-account-misuse-web.yaml"


def serialize_ordered_events(scenario: Scenario) -> list[dict]:
    """
    Serialize a scenario's ordered events.

    Args:
        scenario (Scenario): Scenario whose ordered events should be serialized.

    Returns:
        list[dict]: Serialized source-neutral events.
    """
    return [event.to_dict() for event in scenario.ordered_events()]


def test_canonical_yaml_fixture_files_exist() -> None:
    """
    Verify the documented canonical YAML fixture files are present.

    Returns:
        None: This test asserts fixture paths directly.
    """
    assert BENIGN_FIXTURE_PATH.is_file()
    assert MISUSE_FIXTURE_PATH.is_file()


def test_benign_yaml_fixture_matches_python_canonical_scenario() -> None:
    """
    Verify the benign YAML fixture expands to the canonical Python fixture.

    Returns:
        None: This test asserts exact source-neutral event parity.
    """
    yaml_scenario = load_scenario_from_yaml(BENIGN_FIXTURE_PATH)
    python_scenario = build_benign_internal_web_scenario()

    assert yaml_scenario.id == python_scenario.id
    assert yaml_scenario.name == python_scenario.name
    assert yaml_scenario.seed == python_scenario.seed
    assert yaml_scenario.authored_event_count == 1
    assert yaml_scenario.end_time == python_scenario.end_time
    assert serialize_ordered_events(yaml_scenario) == serialize_ordered_events(python_scenario)
    assert yaml_scenario.answer_key == ()


def test_misuse_yaml_fixture_matches_python_canonical_scenario() -> None:
    """
    Verify the misuse YAML fixture expands to the canonical Python fixture.

    Returns:
        None: This test asserts exact source-neutral event and answer-key parity.
    """
    yaml_scenario = load_scenario_from_yaml(MISUSE_FIXTURE_PATH)
    python_scenario = build_local_account_misuse_web_scenario()

    assert yaml_scenario.id == python_scenario.id
    assert yaml_scenario.name == python_scenario.name
    assert yaml_scenario.seed == python_scenario.seed
    assert yaml_scenario.authored_event_count == 3
    assert yaml_scenario.end_time == python_scenario.end_time
    assert serialize_ordered_events(yaml_scenario) == serialize_ordered_events(python_scenario)
    assert [record.to_dict() for record in yaml_scenario.answer_key] == [
        record.to_dict() for record in python_scenario.answer_key
    ]


def test_canonical_yaml_fixtures_generate_documented_metadata(tmp_path: Path) -> None:
    """
    Verify fixture generation writes documented output paths and metadata behavior.

    Args:
        tmp_path (Path): Pytest temporary output directory.

    Returns:
        None: This test asserts generated output metadata directly.
    """
    benign_output_root = tmp_path / "benign"
    misuse_output_root = tmp_path / "misuse"

    benign_manifest_path = generate_from_yaml(
        BENIGN_FIXTURE_PATH,
        benign_output_root,
        run_id="run-readme-benign",
        generated_at=datetime(2026, 1, 15, 14, 0, 3, tzinfo=timezone.utc),
    )
    misuse_manifest_path = generate_from_yaml(
        MISUSE_FIXTURE_PATH,
        misuse_output_root,
        run_id="run-readme-misuse",
        generated_at=datetime(2026, 1, 15, 3, 12, 29, tzinfo=timezone.utc),
    )
    benign_manifest = read_json(benign_manifest_path)
    misuse_manifest = read_json(misuse_manifest_path)
    benign_events_path = benign_output_root / "logs" / "source-neutral-core" / "generic-normalized" / "events.jsonl"
    misuse_events_path = misuse_output_root / "logs" / "source-neutral-core" / "generic-normalized" / "events.jsonl"

    assert benign_manifest["files"][0]["path"] == "logs/source-neutral-core/generic-normalized/events.jsonl"
    assert benign_manifest["files"][0]["record_count"] == 3
    assert len(read_jsonl(benign_events_path)) == 3
    assert not (benign_output_root / "metadata" / "ground-truth.jsonl").exists()

    assert misuse_manifest["files"][0]["path"] == "logs/source-neutral-core/generic-normalized/events.jsonl"
    assert misuse_manifest["files"][0]["record_count"] == 5
    assert len(read_jsonl(misuse_events_path)) == 5
    assert misuse_manifest["metadata_files"][1]["path"] == "metadata/ground-truth.jsonl"
    assert read_jsonl(misuse_output_root / "metadata" / "ground-truth.jsonl")[0]["label"] == (
        "suspicious_internal_web_download"
    )
