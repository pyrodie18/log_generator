"""
Tests for the Phase 2 command-line interface.
"""

from pathlib import Path

from log_generator.cli import main
from support import canonical_benign_yaml, canonical_misuse_yaml, read_json, read_jsonl


def test_cli_generate_writes_benign_output_tree(tmp_path: Path, capsys) -> None:
    """
    Verify the generate command writes canonical benign output.

    Args:
        tmp_path (Path): Pytest temporary directory.
        capsys (CaptureFixture): Pytest stdout and stderr capture fixture.

    Returns:
        None: This test asserts generated files and command output directly.
    """
    scenario_path = tmp_path / "benign.yaml"
    output_root = tmp_path / "output"
    scenario_path.write_text(canonical_benign_yaml(), encoding="utf-8")

    exit_code = main(
        [
            "generate",
            "--scenario",
            str(scenario_path),
            "--output",
            str(output_root),
            "--run-id",
            "run-cli-benign",
            "--generated-at",
            "2026-01-15T14:00:03Z",
        ]
    )
    captured = capsys.readouterr()
    manifest = read_json(output_root / "manifest.json")
    events = read_jsonl(output_root / "logs" / "source-neutral-core" / "generic-normalized" / "events.jsonl")

    assert exit_code == 0
    assert captured.out == f"wrote manifest: {output_root / 'manifest.json'}\n"
    assert captured.err == ""
    assert manifest["run"]["run_id"] == "run-cli-benign"
    assert manifest["generated_at"] == "2026-01-15T14:00:03+00:00"
    assert manifest["files"][0]["record_count"] == 3
    assert len(events) == 3
    assert not (output_root / "metadata" / "ground-truth.jsonl").exists()


def test_cli_generate_writes_misuse_ground_truth(tmp_path: Path, capsys) -> None:
    """
    Verify the generate command writes canonical misuse output including ground truth.

    Args:
        tmp_path (Path): Pytest temporary directory.
        capsys (CaptureFixture): Pytest stdout and stderr capture fixture.

    Returns:
        None: This test asserts generated metadata directly.
    """
    scenario_path = tmp_path / "misuse.yaml"
    output_root = tmp_path / "output"
    scenario_path.write_text(canonical_misuse_yaml(), encoding="utf-8")

    exit_code = main(
        [
            "generate",
            "--scenario",
            str(scenario_path),
            "--output",
            str(output_root),
            "--run-id",
            "run-cli-misuse",
            "--generated-at",
            "2026-01-15T03:12:29Z",
        ]
    )
    captured = capsys.readouterr()
    manifest = read_json(output_root / "manifest.json")
    ground_truth = read_jsonl(output_root / "metadata" / "ground-truth.jsonl")

    assert exit_code == 0
    assert captured.err == ""
    assert manifest["files"][0]["record_count"] == 5
    assert manifest["metadata_files"][1]["path"] == "metadata/ground-truth.jsonl"
    assert ground_truth[0]["label"] == "suspicious_internal_web_download"


def test_cli_generate_writes_zeek_output_when_requested(tmp_path: Path, capsys) -> None:
    """
    Verify the generate command writes Zeek streams when requested by YAML.

    Args:
        tmp_path (Path): Pytest temporary directory.
        capsys (CaptureFixture): Pytest stdout and stderr capture fixture.

    Returns:
        None: This test asserts generated Zeek files and manifest entries.
    """
    scenario_path = tmp_path / "benign-zeek.yaml"
    output_root = tmp_path / "output"
    scenario_path.write_text(
        canonical_benign_yaml().replace(
            "  - generic-normalized",
            "  - generic-normalized\n  - zeek",
        ),
        encoding="utf-8",
    )

    exit_code = main(
        [
            "generate",
            "--scenario",
            str(scenario_path),
            "--output",
            str(output_root),
            "--run-id",
            "run-cli-benign-zeek",
            "--generated-at",
            "2026-01-15T14:00:03Z",
        ]
    )
    captured = capsys.readouterr()
    manifest = read_json(output_root / "manifest.json")
    file_paths = [entry["path"] for entry in manifest["files"]]

    assert exit_code == 0
    assert captured.err == ""
    assert file_paths == [
        "logs/source-neutral-core/generic-normalized/events.jsonl",
        "logs/zeek-sensor-01/zeek/conn.log",
        "logs/zeek-sensor-01/zeek/dns.log",
        "logs/zeek-sensor-01/zeek/http.log",
    ]
    assert manifest["requested_output_families"] == ["generic-normalized", "zeek"]
    assert (output_root / "logs" / "zeek-sensor-01" / "zeek" / "conn.log").exists()
    assert manifest["files"][1]["format"] == "zeek-tsv"
    assert manifest["files"][1]["record_count"] == 2


def test_cli_generate_reports_validation_errors_without_tracebacks(tmp_path: Path, capsys) -> None:
    """
    Verify expected validation errors return non-zero with concise stderr.

    Args:
        tmp_path (Path): Pytest temporary directory.
        capsys (CaptureFixture): Pytest stdout and stderr capture fixture.

    Returns:
        None: This test asserts command failure behavior directly.
    """
    scenario_path = tmp_path / "bad.yaml"
    output_root = tmp_path / "output"
    scenario_path.write_text(canonical_benign_yaml().replace("user-alice", "user-missing"), encoding="utf-8")

    exit_code = main(
        [
            "generate",
            "--scenario",
            str(scenario_path),
            "--output",
            str(output_root),
            "--generated-at",
            "2026-01-15T14:00:03Z",
        ]
    )
    captured = capsys.readouterr()

    assert exit_code == 1
    assert captured.out == ""
    assert captured.err.startswith("error: ")
    assert "unknown user" in captured.err
    assert "Traceback" not in captured.err
    assert not (output_root / "manifest.json").exists()
