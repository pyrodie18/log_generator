"""
Tests for reusable primitive value checks.
"""

import pytest

from log_generator.core.value_checks import (
    is_http_status_code,
    is_integer,
    is_ip_address,
    is_non_negative_integer,
    is_non_negative_number,
    is_number,
    is_port_number,
    require_ip_address,
    require_port_number,
)


def test_integer_checks_reject_booleans() -> None:
    """
    Verify integer helpers do not accept bool values through Python's int inheritance.

    Returns:
        None: This test asserts primitive check results directly.
    """
    assert is_integer(0)
    assert is_non_negative_integer(10)
    assert not is_integer(True)
    assert not is_non_negative_integer(False)
    assert not is_non_negative_integer(-1)


def test_number_checks_reject_booleans_and_negative_values() -> None:
    """
    Verify numeric helpers distinguish type checks from range checks.

    Returns:
        None: This test asserts primitive check results directly.
    """
    assert is_number(-1.5)
    assert is_non_negative_number(0.25)
    assert not is_number(True)
    assert not is_non_negative_number(-0.25)


def test_range_checks_support_optional_values() -> None:
    """
    Verify reusable range helpers can be used for optional and required fields.

    Returns:
        None: This test asserts primitive check results directly.
    """
    assert is_port_number(65535)
    assert is_port_number(None, allow_none=True)
    assert not is_port_number(None)
    assert not is_port_number(65536)
    assert is_http_status_code(599)
    assert not is_http_status_code(99)


def test_ip_address_checks_accept_ipv4_and_ipv6() -> None:
    """
    Verify IP address checks accept valid address strings only.

    Returns:
        None: This test asserts primitive check results directly.
    """
    assert is_ip_address("10.10.20.21")
    assert is_ip_address("2001:db8::1")
    assert is_ip_address(None, allow_none=True)
    assert not is_ip_address("not an address")
    assert not is_ip_address(1234)


def test_require_helpers_raise_field_specific_errors() -> None:
    """
    Verify raise-on-invalid helpers include the caller's field path.

    Returns:
        None: This test asserts validation failures directly.
    """
    with pytest.raises(ValueError, match="network.source_port must be between 0 and 65535"):
        require_port_number("network.source_port", 70000)

    with pytest.raises(ValueError, match="source_ip must be a valid IP address"):
        require_ip_address("source_ip", "not an address")
