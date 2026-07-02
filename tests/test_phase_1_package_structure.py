"""
Tests for the Phase 1 package skeleton.
"""

import importlib

import log_generator


def test_existing_public_api_remains_available() -> None:
    """
    Verify Phase 1 package additions do not remove the existing public API.

    Returns:
        None: This test asserts the package exports directly.
    """
    assert log_generator.__all__ == ["generate_log_entry"]
    assert callable(log_generator.generate_log_entry)


def test_phase_1_modules_import_cleanly() -> None:
    """
    Verify the Phase 1 core and output modules can be imported.

    Returns:
        None: This test imports each planned module directly.
    """
    module_names = [
        "log_generator.core",
        "log_generator.core.environment",
        "log_generator.core.events",
        "log_generator.core.scenarios",
        "log_generator.core.validation",
        "log_generator.output",
        "log_generator.output.jsonl",
        "log_generator.output.manifest",
    ]

    for module_name in module_names:
        # Import by name to catch packaging mistakes without depending on implementation details yet.
        assert importlib.import_module(module_name).__name__ == module_name
