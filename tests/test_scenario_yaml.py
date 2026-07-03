"""
Tests for Phase 2 YAML scenario parsing and structural validation.
"""

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from log_generator.core.scenarios import build_benign_internal_web_scenario, build_local_account_misuse_web_scenario
from log_generator.scenario_yaml import (
    DEFAULT_OUTPUT_FAMILIES,
    SUPPORTED_SCHEMA_VERSION,
    ScenarioYamlError,
    build_scenario_from_yaml_text,
    load_scenario_yaml,
    parse_scenario_yaml_text,
)


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
"""


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
    assert yaml_events[4]["parent_event_id"] == "evt-misuse-web-003"
    assert yaml_events[4]["metadata"] == {
        "download_classification": "download",
        "file_name": "archive.tar.gz",
    }


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
    at: +500ms
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

    assert parsed.events[0].timestamp == datetime(2026, 1, 15, 14, 0, 0, 500000, tzinfo=timezone.utc)
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
