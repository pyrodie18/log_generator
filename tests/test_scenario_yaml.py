"""
Tests for Phase 2 YAML scenario parsing and structural validation.
"""

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from log_generator.core.environment import build_linux_mini_lab
from log_generator.core.scenarios import build_benign_internal_web_scenario, build_local_account_misuse_web_scenario
from log_generator.scenario_yaml import (
    DEFAULT_OUTPUT_FAMILIES,
    SUPPORTED_SCHEMA_VERSION,
    ScenarioYamlError,
    build_scenario_from_yaml_text,
    generate_from_yaml,
    load_scenario_yaml,
    load_scenario_from_yaml,
    parse_scenario_yaml_text,
)
from support import canonical_benign_yaml, canonical_misuse_yaml, read_json, read_jsonl


def minimal_yaml(events: str, extra_top_level: str = "") -> str:
    """
    Build a minimal valid YAML scenario around event text.

    Args:
        events (str): YAML event list body to include after the events key.
        extra_top_level (str): Extra top-level YAML text to append.

    Returns:
        str: Complete YAML scenario document.
    """
    return f"""
schema_version: scenario/v0.1
id: scenario-yaml-test
name: YAML Test Scenario
seed: 3003
environment:
  id: linux-mini-lab
  version: "0.1"
time_range:
  start: 2026-01-15T14:00:00Z
  end: 2026-01-15T14:10:00Z
events:
{events}
{extra_top_level}
"""


def assert_yaml_error_contains(text: str, expected: str) -> None:
    """
    Assert parsing YAML raises a validation error containing expected text.

    Args:
        text (str): YAML scenario text to parse.
        expected (str): Text expected in the validation error.

    Returns:
        None: This helper asserts the validation error message directly.
    """
    with pytest.raises(ScenarioYamlError) as error_info:
        parse_scenario_yaml_text(text)

    assert expected in str(error_info.value)


def assert_yaml_build_error_contains(text: str, expected: str) -> None:
    """
    Assert building a scenario from YAML raises a validation error containing expected text.

    Args:
        text (str): YAML scenario text to build.
        expected (str): Text expected in the validation error.

    Returns:
        None: This helper asserts the validation error message directly.
    """
    with pytest.raises(ScenarioYamlError) as error_info:
        build_scenario_from_yaml_text(text)

    assert expected in str(error_info.value)


def serialized_events_from_scenario(scenario) -> list[dict]:
    """
    Serialize a scenario's ordered events.

    Args:
        scenario: Scenario whose ordered events should be serialized.

    Returns:
        list[dict]: Serialized ordered source-neutral events.
    """
    return [event.to_dict() for event in scenario.ordered_events()]


def test_parse_canonical_style_web_request_top_level_fields() -> None:
    """
    Verify a canonical-style web request scenario parses top-level fields and relative timing.

    Returns:
        None: This test asserts parsed document fields directly.
    """
    parsed = parse_scenario_yaml_text(
        minimal_yaml(
            """
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
        )
    )

    assert parsed.schema_version == SUPPORTED_SCHEMA_VERSION
    assert parsed.scenario_id == "scenario-yaml-test"
    assert parsed.name == "YAML Test Scenario"
    assert parsed.seed == 3003
    assert parsed.environment_id == "linux-mini-lab"
    assert parsed.environment_version == "0.1"
    assert parsed.start_time == datetime(2026, 1, 15, 14, 0, tzinfo=timezone.utc)
    assert parsed.end_time == datetime(2026, 1, 15, 14, 10, tzinfo=timezone.utc)
    assert parsed.output_families == DEFAULT_OUTPUT_FAMILIES
    assert len(parsed.events) == 1
    assert parsed.events[0].event_id == "evt-benign-web-003"
    assert parsed.events[0].event_type == "web_request"
    assert parsed.events[0].timestamp == datetime(2026, 1, 15, 14, 0, 2, tzinfo=timezone.utc)


def test_benign_yaml_converts_to_phase_1_canonical_scenario_events() -> None:
    """
    Verify canonical benign YAML expands through the Phase 1 scenario primitives.

    Returns:
        None: This test asserts exact event parity with the Python fixture.
    """
    yaml_scenario = build_scenario_from_yaml_text(canonical_benign_yaml())
    fixture_scenario = build_benign_internal_web_scenario()

    assert yaml_scenario.id == fixture_scenario.id
    assert yaml_scenario.name == fixture_scenario.name
    assert yaml_scenario.seed == fixture_scenario.seed
    assert yaml_scenario.authored_event_count == 1
    assert serialized_events_from_scenario(yaml_scenario) == serialized_events_from_scenario(fixture_scenario)


def test_misuse_yaml_converts_to_phase_1_canonical_scenario_events() -> None:
    """
    Verify canonical misuse YAML expands through the Phase 1 scenario primitives.

    Returns:
        None: This test asserts exact event parity with the Python fixture.
    """
    yaml_scenario = build_scenario_from_yaml_text(canonical_misuse_yaml())
    fixture_scenario = build_local_account_misuse_web_scenario()
    yaml_events = serialized_events_from_scenario(yaml_scenario)

    assert yaml_scenario.id == fixture_scenario.id
    assert yaml_scenario.name == fixture_scenario.name
    assert yaml_scenario.seed == fixture_scenario.seed
    assert yaml_scenario.authored_event_count == 3
    assert yaml_events == serialized_events_from_scenario(fixture_scenario)
    assert [record.to_dict() for record in yaml_scenario.answer_key] == [
        record.to_dict() for record in fixture_scenario.answer_key
    ]
    assert yaml_events[4]["parent_event_id"] == "evt-misuse-web-003"
    assert yaml_events[4]["metadata"] == {
        "download_classification": "download",
        "file_name": "archive.tar.gz",
    }


def test_answer_key_can_reference_generated_helper_event() -> None:
    """
    Verify answer-key references can target generated helper event IDs.

    Returns:
        None: This test asserts answer-key conversion directly.
    """
    scenario = build_scenario_from_yaml_text(
        canonical_benign_yaml()
        + """
answer_key:
  - label: benign_dns_helper
    primary_event_id: evt-benign-web-001
    supporting_event_ids:
      - evt-benign-web-002
      - evt-benign-web-003
    description: The generated DNS helper for the benign web request.
"""
    )

    assert scenario.answer_key[0].to_dict() == {
        "scenario_id": "scenario-benign-internal-web",
        "correlation_id": "corr-benign-internal-web-001",
        "label": "benign_dns_helper",
        "primary_event_id": "evt-benign-web-001",
        "supporting_event_ids": ["evt-benign-web-002", "evt-benign-web-003"],
        "description": "The generated DNS helper for the benign web request.",
    }


def test_load_scenario_from_yaml_returns_expanded_scenario(tmp_path: Path) -> None:
    """
    Verify the Task 8 load API returns an expanded scenario without writing output.

    Args:
        tmp_path (Path): Pytest temporary directory.

    Returns:
        None: This test asserts loaded scenario details directly.
    """
    scenario_path = tmp_path / "benign.yaml"
    scenario_path.write_text(canonical_benign_yaml(), encoding="utf-8")

    scenario = load_scenario_from_yaml(scenario_path)

    assert scenario.id == "scenario-benign-internal-web"
    assert scenario.event_ids() == (
        "evt-benign-web-001",
        "evt-benign-web-002",
        "evt-benign-web-003",
    )
    assert not (tmp_path / "manifest.json").exists()


def test_generate_from_yaml_writes_manifest_and_generic_output(tmp_path: Path) -> None:
    """
    Verify the Task 8 generate API writes the complete generic output tree.

    Args:
        tmp_path (Path): Pytest temporary directory.

    Returns:
        None: This test asserts generated files and manifest metadata directly.
    """
    scenario_path = tmp_path / "misuse.yaml"
    output_root = tmp_path / "output"
    scenario_path.write_text(canonical_misuse_yaml(), encoding="utf-8")

    manifest_path = generate_from_yaml(
        scenario_path,
        output_root,
        run_id="run-yaml-misuse",
        generated_at=datetime(2026, 1, 15, 3, 12, 29, tzinfo=timezone.utc),
    )
    manifest = read_json(manifest_path)
    events = read_jsonl(output_root / "logs" / "source-neutral-core" / "generic-normalized" / "events.jsonl")
    ground_truth = read_jsonl(output_root / "metadata" / "ground-truth.jsonl")

    assert manifest_path == output_root / "manifest.json"
    assert manifest["run"]["run_id"] == "run-yaml-misuse"
    assert manifest["generated_at"] == "2026-01-15T03:12:29+00:00"
    assert manifest["files"][0]["record_count"] == 5
    assert len(events) == 5
    assert ground_truth[0]["label"] == "suspicious_internal_web_download"


def test_generate_from_yaml_uses_deterministic_default_run_id(tmp_path: Path) -> None:
    """
    Verify omitted run_id uses a deterministic scenario-based default.

    Args:
        tmp_path (Path): Pytest temporary directory.

    Returns:
        None: This test asserts manifest run metadata directly.
    """
    scenario_path = tmp_path / "benign.yaml"
    output_root = tmp_path / "output"
    scenario_path.write_text(canonical_benign_yaml(), encoding="utf-8")

    manifest_path = generate_from_yaml(
        scenario_path,
        output_root,
        generated_at=datetime(2026, 1, 15, 14, 0, 3, tzinfo=timezone.utc),
    )
    manifest = read_json(manifest_path)

    assert manifest["run"]["run_id"] == "run-scenario-benign-internal-web"


def test_yaml_api_accepts_environment_registry_override() -> None:
    """
    Verify callers can provide an environment registry for versioned environment resolution.

    Returns:
        None: This test asserts custom registry behavior directly.
    """
    custom_environment = replace(build_linux_mini_lab(), version="9.9")
    scenario = build_scenario_from_yaml_text(
        canonical_benign_yaml().replace('version: "0.1"', 'version: "9.9"'),
        environment_registry={custom_environment.id: custom_environment},
    )

    assert scenario.environment_version == "9.9"


def test_yaml_conversion_generates_deterministic_correlation_id_when_omitted() -> None:
    """
    Verify YAML conversion derives stable correlation IDs for top-level activity.

    Returns:
        None: This test asserts deterministic generated correlation IDs directly.
    """
    scenario = build_scenario_from_yaml_text(
        minimal_yaml(
            """
  - id: evt-web-003
    type: web_request
    at: +2s
    actor: user-alice
    source_host: linux-ws-01
    service: svc-web-http
    method: GET
    path: /
"""
        )
    )

    assert scenario.correlation_ids() == ("corr-scenario-yaml-test-001",)


def test_attack_chain_unknown_primary_event_is_rejected() -> None:
    """
    Verify attack-chain primary event references must resolve after expansion.

    Returns:
        None: This test asserts build-time validation error text directly.
    """
    assert_yaml_build_error_contains(
        canonical_benign_yaml()
        + """
attack_chain:
  - id: step-missing
    name: Missing step
    primary_event_id: evt-missing
""",
        "attack_chain[0].primary_event_id: 'evt-missing' is invalid because event reference does not resolve",
    )


def test_answer_key_unknown_supporting_event_is_rejected() -> None:
    """
    Verify answer-key supporting event references must resolve after expansion.

    Returns:
        None: This test asserts build-time validation error text directly.
    """
    assert_yaml_build_error_contains(
        canonical_benign_yaml()
        + """
answer_key:
  - label: bad_reference
    primary_event_id: evt-benign-web-003
    supporting_event_ids:
      - evt-missing
    description: Bad supporting event reference.
""",
        "answer_key[0].supporting_event_ids[0]: 'evt-missing' is invalid because event reference does not resolve",
    )


def test_answer_key_missing_required_field_is_rejected() -> None:
    """
    Verify answer-key records require the fields needed for ground-truth output.

    Returns:
        None: This test asserts build-time validation error text directly.
    """
    assert_yaml_build_error_contains(
        canonical_benign_yaml()
        + """
answer_key:
  - label: missing_description
    primary_event_id: evt-benign-web-003
""",
        "answer_key[0].description: None is invalid because field is required",
    )


def test_attack_chain_invalid_technique_id_is_rejected() -> None:
    """
    Verify attack-chain technique IDs use the supported simple T-number form.

    Returns:
        None: This test asserts build-time validation error text directly.
    """
    assert_yaml_build_error_contains(
        canonical_benign_yaml()
        + """
attack_chain:
  - id: step-invalid-technique
    name: Invalid technique
    primary_event_id: evt-benign-web-003
    technique_id: T1105.001
""",
        "attack_chain[0].technique_id: 'T1105.001' is invalid because expected ATT&CK technique ID like 'T1105'",
    )


def test_environment_shorthand_uses_supported_builtin_version() -> None:
    """
    Verify environment shorthand resolves to the built-in linux-mini-lab version.

    Returns:
        None: This test asserts environment shorthand handling directly.
    """
    parsed = parse_scenario_yaml_text(
        """
schema_version: scenario/v0.1
id: scenario-yaml-test
name: YAML Test Scenario
seed: 3003
environment: linux-mini-lab
time_range:
  start: 2026-01-15T14:00:00Z
events:
  - id: evt-benign-web-003
    type: web_request
    at: +2s
    actor: user-alice
    source_host: linux-ws-01
    service: svc-web-http
    method: GET
    path: /
"""
    )

    assert parsed.environment_id == "linux-mini-lab"
    assert parsed.environment_version == "0.1"
    assert parsed.end_time is None


def test_load_scenario_yaml_reads_file(tmp_path: Path) -> None:
    """
    Verify YAML scenario loading from disk uses UTF-8 text.

    Args:
        tmp_path (Path): Pytest temporary directory.

    Returns:
        None: This test asserts file loading directly.
    """
    scenario_path = tmp_path / "scenario.yaml"
    scenario_path.write_text(
        minimal_yaml(
            """
  - id: evt-benign-web-003
    type: web_request
    at: +2s
    actor: user-alice
    source_host: linux-ws-01
    service: svc-web-http
    method: GET
    path: /
"""
        ),
        encoding="utf-8",
    )

    assert load_scenario_yaml(scenario_path).scenario_id == "scenario-yaml-test"


def test_after_delay_resolves_from_earlier_authored_event() -> None:
    """
    Verify dependency-based timing resolves from an earlier event.

    Returns:
        None: This test asserts resolved timestamps and delay values directly.
    """
    parsed = parse_scenario_yaml_text(
        minimal_yaml(
            """
  - id: evt-login
    type: linux_local_login
    at: +0s
    actor: user-alice
    target_host: linux-ws-01
    login_method: local_console
  - id: evt-web
    type: web_request
    after: evt-login
    delay: 18s
    actor: user-alice
    source_host: linux-ws-01
    service: svc-web-http
    method: GET
    path: /admin
"""
        ).replace("2026-01-15T14:10:00Z", "2026-01-15T16:00:00Z")
    )

    assert parsed.events[1].after == "evt-login"
    assert parsed.events[1].delay == timedelta(seconds=18)
    assert parsed.events[1].timestamp == datetime(2026, 1, 15, 14, 0, 18, tzinfo=timezone.utc)


def test_supported_duration_units_parse_predictably() -> None:
    """
    Verify milliseconds, minutes, and hours are supported as single-unit durations.

    Returns:
        None: This test asserts resolved event timestamps directly.
    """
    parsed = parse_scenario_yaml_text(
        minimal_yaml(
            """
  - id: evt-ms
    type: web_request
    at: +2500ms
    actor: user-alice
    source_host: linux-ws-01
    service: svc-web-http
    method: GET
    path: /
  - id: evt-min
    type: web_request
    at: +2m
    actor: user-alice
    source_host: linux-ws-01
    service: svc-web-http
    method: GET
    path: /
  - id: evt-hour
    type: web_request
    at: +1h
    actor: user-alice
    source_host: linux-ws-01
    service: svc-web-http
    method: GET
    path: /
"""
        ).replace("2026-01-15T14:10:00Z", "2026-01-15T16:00:00Z")
    )

    assert parsed.events[0].timestamp == datetime(2026, 1, 15, 14, 0, 2, 500000, tzinfo=timezone.utc)
    assert parsed.events[1].timestamp == datetime(2026, 1, 15, 14, 2, tzinfo=timezone.utc)
    assert parsed.events[2].timestamp == datetime(2026, 1, 15, 15, 0, tzinfo=timezone.utc)


def test_empty_yaml_is_rejected() -> None:
    """
    Verify empty YAML documents are rejected.

    Returns:
        None: This test asserts validation error text directly.
    """
    assert_yaml_error_contains("", "must not be empty")


def test_multi_document_yaml_is_rejected() -> None:
    """
    Verify multi-document YAML files are rejected for Phase 2.

    Returns:
        None: This test asserts validation error text directly.
    """
    assert_yaml_error_contains("---\nid: one\n---\nid: two\n", "multi-document YAML is not supported yet")


def test_missing_required_top_level_field_is_reported() -> None:
    """
    Verify missing required top-level fields include field paths.

    Returns:
        None: This test asserts validation error text directly.
    """
    assert_yaml_error_contains(
        """
schema_version: scenario/v0.1
id: scenario-yaml-test
name: YAML Test Scenario
environment: linux-mini-lab
time_range:
  start: 2026-01-15T14:00:00Z
events:
  - id: evt-benign-web-003
    type: web_request
    at: +2s
    actor: user-alice
    source_host: linux-ws-01
    service: svc-web-http
    method: GET
    path: /
""",
        "seed: None is invalid because field is required",
    )


def test_unsupported_schema_version_is_rejected() -> None:
    """
    Verify unsupported schema versions fail before scenario conversion.

    Returns:
        None: This test asserts validation error text directly.
    """
    assert_yaml_error_contains(
        minimal_yaml(
            """
  - id: evt-benign-web-003
    type: web_request
    at: +2s
    actor: user-alice
    source_host: linux-ws-01
    service: svc-web-http
    method: GET
    path: /
"""
        ).replace("schema_version: scenario/v0.1", "schema_version: scenario/v9"),
        "schema_version: 'scenario/v9' is invalid because supported value is 'scenario/v0.1'",
    )


def test_unknown_top_level_field_is_rejected() -> None:
    """
    Verify unknown top-level fields are validation errors.

    Returns:
        None: This test asserts validation error text directly.
    """
    assert_yaml_error_contains(
        minimal_yaml(
            """
  - id: evt-benign-web-003
    type: web_request
    at: +2s
    actor: user-alice
    source_host: linux-ws-01
    service: svc-web-http
    method: GET
    path: /
""",
            extra_top_level="unexpected_field: true",
        ),
        "unexpected_field: True is invalid because unknown field",
    )


def test_zeek_output_family_loads_with_generic_normalized() -> None:
    """
    Verify Zeek can be requested alongside generic normalized output.

    Returns:
        None: This test asserts parsed output families directly.
    """
    parsed = parse_scenario_yaml_text(
        minimal_yaml(
            """
  - id: evt-benign-web-003
    type: web_request
    at: +2s
    actor: user-alice
    source_host: linux-ws-01
    service: svc-web-http
    method: GET
    path: /
""",
            extra_top_level="""
output_families:
  - generic-normalized
  - zeek
""",
        )
    )

    assert parsed.output_families == ("generic-normalized", "zeek")


def test_zeek_only_output_family_loads() -> None:
    """
    Verify Zeek can be the only requested output family.

    Returns:
        None: This test asserts parsed output families directly.
    """
    parsed = parse_scenario_yaml_text(
        minimal_yaml(
            """
  - id: evt-benign-web-003
    type: web_request
    at: +2s
    actor: user-alice
    source_host: linux-ws-01
    service: svc-web-http
    method: GET
    path: /
""",
            extra_top_level="""
output_families:
  - zeek
""",
        )
    )

    assert parsed.output_families == ("zeek",)


@pytest.mark.parametrize("output_family", ["apache", "auditd", "firewall", "proxy"])
def test_unsupported_source_specific_output_families_are_rejected(output_family: str) -> None:
    """
    Verify future source-specific output families fail explicitly.

    Args:
        output_family (str): Unsupported source-specific output family to request.

    Returns:
        None: This test asserts validation error text directly.
    """
    assert_yaml_error_contains(
        minimal_yaml(
            """
  - id: evt-benign-web-003
    type: web_request
    at: +2s
    actor: user-alice
    source_host: linux-ws-01
    service: svc-web-http
    method: GET
    path: /
""",
            extra_top_level="""
output_families:
  - generic-normalized
  - {output_family}
""".format(output_family=output_family),
        ),
        "output_families[1]: "
        f"'{output_family}' is invalid because source-specific output family is not supported yet",
    )


def test_unknown_output_family_is_rejected() -> None:
    """
    Verify unknown output families fail before generation.

    Returns:
        None: This test asserts validation error text directly.
    """
    assert_yaml_error_contains(
        minimal_yaml(
            """
  - id: evt-benign-web-003
    type: web_request
    at: +2s
    actor: user-alice
    source_host: linux-ws-01
    service: svc-web-http
    method: GET
    path: /
""",
            extra_top_level="""
output_families:
  - generic-normalized
  - custom-family
""",
        ),
        "output_families[1]: 'custom-family' is invalid because unsupported output family",
    )


def test_duplicate_output_family_is_rejected() -> None:
    """
    Verify duplicate output families fail before scenario generation.

    Returns:
        None: This test asserts validation error text directly.
    """
    assert_yaml_error_contains(
        minimal_yaml(
            """
  - id: evt-benign-web-003
    type: web_request
    at: +2s
    actor: user-alice
    source_host: linux-ws-01
    service: svc-web-http
    method: GET
    path: /
""",
            extra_top_level="""
output_families:
  - generic-normalized
  - zeek
  - zeek
""",
        ),
        "output_families[2]: 'zeek' is invalid because duplicate output family",
    )


def test_unknown_event_field_is_rejected() -> None:
    """
    Verify unknown fields on supported event types are validation errors.

    Returns:
        None: This test asserts validation error text directly.
    """
    assert_yaml_error_contains(
        minimal_yaml(
            """
  - id: evt-benign-web-003
    type: web_request
    at: +2s
    actor: user-alice
    user: alice
    source_host: linux-ws-01
    service: svc-web-http
    method: GET
    path: /
"""
        ),
        "events[0].user: 'alice' is invalid because unknown field",
    )


def test_duplicate_event_ids_are_rejected() -> None:
    """
    Verify duplicate authored event IDs are validation errors.

    Returns:
        None: This test asserts validation error text directly.
    """
    assert_yaml_error_contains(
        minimal_yaml(
            """
  - id: evt-duplicate
    type: web_request
    at: +1s
    actor: user-alice
    source_host: linux-ws-01
    service: svc-web-http
    method: GET
    path: /
  - id: evt-duplicate
    type: web_request
    at: +2s
    actor: user-alice
    source_host: linux-ws-01
    service: svc-web-http
    method: GET
    path: /
"""
        ),
        "events[1].id: 'evt-duplicate' is invalid because duplicate event ID",
    )


def test_missing_event_timing_is_rejected() -> None:
    """
    Verify events must include at or after.

    Returns:
        None: This test asserts validation error text directly.
    """
    assert_yaml_error_contains(
        minimal_yaml(
            """
  - id: evt-benign-web-003
    type: web_request
    actor: user-alice
    source_host: linux-ws-01
    service: svc-web-http
    method: GET
    path: /
"""
        ),
        "events[0]: None is invalid because expected either 'at' or 'after'",
    )


def test_bad_dependency_is_rejected() -> None:
    """
    Verify after references must point to earlier authored events.

    Returns:
        None: This test asserts validation error text directly.
    """
    assert_yaml_error_contains(
        minimal_yaml(
            """
  - id: evt-web
    type: web_request
    after: evt-missing
    delay: 18s
    actor: user-alice
    source_host: linux-ws-01
    service: svc-web-http
    method: GET
    path: /admin
"""
        ),
        "events[0].after: 'evt-missing' is invalid because event is not defined before this event",
    )


def test_naive_timestamp_is_rejected() -> None:
    """
    Verify timestamps without timezone information are rejected.

    Returns:
        None: This test asserts validation error text directly.
    """
    assert_yaml_error_contains(
        minimal_yaml(
            """
  - id: evt-benign-web-003
    type: web_request
    at: +2s
    actor: user-alice
    source_host: linux-ws-01
    service: svc-web-http
    method: GET
    path: /
"""
        ).replace("2026-01-15T14:00:00Z", "2026-01-15T14:00:00"),
        "time_range.start",
    )


def test_compound_duration_is_rejected() -> None:
    """
    Verify compound durations remain unsupported in Milestone 1.

    Returns:
        None: This test asserts validation error text directly.
    """
    assert_yaml_error_contains(
        minimal_yaml(
            """
  - id: evt-benign-web-003
    type: web_request
    at: +1m30s
    actor: user-alice
    source_host: linux-ws-01
    service: svc-web-http
    method: GET
    path: /
"""
        ),
        "events[0].at: '+1m30s' is invalid because expected a simple duration",
    )


def test_delay_without_after_is_rejected() -> None:
    """
    Verify delay cannot appear without after.

    Returns:
        None: This test asserts validation error text directly.
    """
    assert_yaml_error_contains(
        minimal_yaml(
            """
  - id: evt-benign-web-003
    type: web_request
    at: +2s
    delay: 1s
    actor: user-alice
    source_host: linux-ws-01
    service: svc-web-http
    method: GET
    path: /
"""
        ),
        "events[0].delay: '1s' is invalid because delay may appear only with after",
    )


def test_unknown_user_is_rejected_by_yaml_environment_validation() -> None:
    """
    Verify YAML actor references must resolve through the environment.

    Returns:
        None: This test asserts validation error text directly.
    """
    assert_yaml_error_contains(
        minimal_yaml(
            """
  - id: evt-benign-web-003
    type: web_request
    at: +2s
    actor: user-missing
    source_host: linux-ws-01
    service: svc-web-http
    method: GET
    path: /
"""
        ),
        "events[0].actor: 'user-missing' is invalid because unknown user",
    )


def test_unknown_source_host_is_rejected_by_yaml_environment_validation() -> None:
    """
    Verify YAML source host references must resolve through the environment.

    Returns:
        None: This test asserts validation error text directly.
    """
    assert_yaml_error_contains(
        minimal_yaml(
            """
  - id: evt-benign-web-003
    type: web_request
    at: +2s
    actor: user-alice
    source_host: linux-ws-99
    service: svc-web-http
    method: GET
    path: /
"""
        ),
        "events[0].source_host: 'linux-ws-99' is invalid because unknown host",
    )


def test_unknown_service_is_rejected_by_yaml_environment_validation() -> None:
    """
    Verify YAML service references must resolve through the environment.

    Returns:
        None: This test asserts validation error text directly.
    """
    assert_yaml_error_contains(
        minimal_yaml(
            """
  - id: evt-benign-web-003
    type: web_request
    at: +2s
    actor: user-alice
    source_host: linux-ws-01
    service: svc-web-missing
    method: GET
    path: /
"""
        ),
        "events[0].service: 'svc-web-missing' is invalid because unknown service",
    )


def test_invalid_login_host_is_rejected_by_yaml_environment_validation() -> None:
    """
    Verify successful local logins must target one of the user's valid login hosts.

    Returns:
        None: This test asserts validation error text directly.
    """
    assert_yaml_error_contains(
        minimal_yaml(
            """
  - id: evt-login
    type: linux_local_login
    at: +0s
    actor: user-alice
    target_host: linux-ws-02
    login_method: local_console
"""
        ),
        "events[0].target_host: 'linux-ws-02' is invalid because user 'user-alice' cannot log in to 'linux-ws-02'",
    )


def test_invalid_login_source_ip_is_rejected_by_yaml_validation() -> None:
    """
    Verify YAML login events reject malformed source IP addresses with a field path.

    Returns:
        None: This test asserts validation error text directly.
    """
    assert_yaml_error_contains(
        minimal_yaml(
            """
  - id: evt-login
    type: linux_local_login
    at: +0s
    actor: user-alice
    target_host: linux-ws-01
    login_method: local_console
    source_ip: not an address
"""
        ),
        "events[0].source_ip: 'not an address' is invalid because must be a valid IP address",
    )


def test_web_request_to_non_http_service_is_rejected() -> None:
    """
    Verify web_request events cannot target non-HTTP services.

    Returns:
        None: This test asserts validation error text directly.
    """
    assert_yaml_error_contains(
        minimal_yaml(
            """
  - id: evt-web-003
    type: web_request
    at: +2s
    actor: user-alice
    source_host: linux-ws-01
    service: svc-web-ssh
    method: GET
    path: /
"""
        ),
        "events[0].service: 'svc-web-ssh' is invalid because web_request events must target an HTTP service",
    )


def test_bad_route_is_rejected_by_yaml_environment_validation() -> None:
    """
    Verify web request paths must match known service routes unless status_code is explicit.

    Returns:
        None: This test asserts validation error text directly.
    """
    assert_yaml_error_contains(
        minimal_yaml(
            """
  - id: evt-web-003
    type: web_request
    at: +2s
    actor: user-alice
    source_host: linux-ws-01
    service: svc-web-http
    method: POST
    path: /admin/archive.tar.gz
"""
        ),
        "route 'POST /admin/archive.tar.gz' is not defined for service 'svc-web-http'",
    )


def test_unknown_route_can_use_explicit_status_code() -> None:
    """
    Verify explicit status_code lets authors model an unknown HTTP route.

    Returns:
        None: This test asserts parsing succeeds directly.
    """
    parsed = parse_scenario_yaml_text(
        minimal_yaml(
            """
  - id: evt-web-003
    type: web_request
    at: +2s
    actor: user-alice
    source_host: linux-ws-01
    service: svc-web-http
    method: POST
    path: /admin/archive.tar.gz
    status_code: 404
"""
        )
    )

    assert parsed.events[0].raw["status_code"] == 404


def test_invalid_path_is_rejected_by_yaml_environment_validation() -> None:
    """
    Verify web request paths must start with a slash.

    Returns:
        None: This test asserts validation error text directly.
    """
    assert_yaml_error_contains(
        minimal_yaml(
            """
  - id: evt-web-003
    type: web_request
    at: +2s
    actor: user-alice
    source_host: linux-ws-01
    service: svc-web-http
    method: GET
    path: admin
"""
        ),
        "events[0].path: 'admin' is invalid because path must start with '/'",
    )


def test_invalid_status_code_range_is_rejected() -> None:
    """
    Verify explicit HTTP status codes must be in the valid range.

    Returns:
        None: This test asserts validation error text directly.
    """
    assert_yaml_error_contains(
        minimal_yaml(
            """
  - id: evt-web-003
    type: web_request
    at: +2s
    actor: user-alice
    source_host: linux-ws-01
    service: svc-web-http
    method: GET
    path: /
    status_code: 99
"""
        ),
        "events[0].status_code: 99 is invalid because status_code must be between 100 and 599",
    )


def test_invalid_shared_detail_override_is_rejected_with_field_path() -> None:
    """
    Verify authored shared-detail overrides fail with nested YAML field paths.

    Returns:
        None: This test asserts validation error text directly.
    """
    assert_yaml_error_contains(
        minimal_yaml(
            """
  - id: evt-web-003
    type: web_request
    at: +3s
    actor: user-alice
    source_host: linux-ws-01
    service: svc-web-http
    method: GET
    path: /
    network:
      source_port: 70000
"""
        ),
        "events[0].network.source_port: 70000 is invalid because must be between 0 and 65535",
    )


def test_invalid_attack_technique_id_is_rejected() -> None:
    """
    Verify ATT&CK technique IDs use the supported simple T-number form.

    Returns:
        None: This test asserts validation error text directly.
    """
    assert_yaml_error_contains(
        minimal_yaml(
            """
  - id: evt-web-003
    type: web_request
    at: +2s
    actor: user-alice
    source_host: linux-ws-01
    service: svc-web-http
    method: GET
    path: /
    attack:
      technique_id: T1105.001
"""
        ),
        "events[0].attack.technique_id: 'T1105.001' is invalid because expected ATT&CK technique ID like 'T1105'",
    )


def test_unsupported_noise_profiles_are_rejected_explicitly() -> None:
    """
    Verify noise_profiles fails with the planned unsupported-feature message.

    Returns:
        None: This test asserts validation error text directly.
    """
    assert_yaml_error_contains(
        minimal_yaml(
            """
  - id: evt-web-003
    type: web_request
    at: +2s
    actor: user-alice
    source_host: linux-ws-01
    service: svc-web-http
    method: GET
    path: /
""",
            extra_top_level="""
noise_profiles:
  - id: light-business-hours-web
""",
        ),
        "noise_profiles is not supported yet",
    )


def test_generated_web_helpers_must_remain_inside_time_range() -> None:
    """
    Verify YAML validation rejects web requests whose generated helpers predate scenario start.

    Returns:
        None: This test asserts validation error text directly.
    """
    assert_yaml_error_contains(
        minimal_yaml(
            """
  - id: evt-web-003
    type: web_request
    at: +1s
    actor: user-alice
    source_host: linux-ws-01
    service: svc-web-http
    method: GET
    path: /
"""
        ),
        "generated dns_lookup helper must stay inside time_range",
    )
