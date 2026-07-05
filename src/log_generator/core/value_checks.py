"""
Reusable primitive value validation checks.
"""

from ipaddress import ip_address
from typing import Any


def is_integer(value: Any, allow_none: bool = False) -> bool:
    """
    Return whether a value is an integer, excluding boolean values.

    Args:
        value (Any): Candidate value to check.
        allow_none (bool): Whether None should be treated as valid.

    Returns:
        bool: True when the value is an integer, or when None is allowed and provided.
    """
    if value is None:
        return allow_none

    # bool is a subclass of int, but scenario fields should not accept True or False as numeric values.
    return isinstance(value, int) and not isinstance(value, bool)


def is_non_negative_integer(value: Any, allow_none: bool = False) -> bool:
    """
    Return whether a value is an integer greater than or equal to zero.

    Args:
        value (Any): Candidate value to check.
        allow_none (bool): Whether None should be treated as valid.

    Returns:
        bool: True when the value is a non-negative integer, or when None is allowed and provided.
    """
    if value is None:
        return allow_none

    return is_integer(value) and value >= 0


def is_number(value: Any, allow_none: bool = False) -> bool:
    """
    Return whether a value is numeric, excluding boolean values.

    Args:
        value (Any): Candidate value to check.
        allow_none (bool): Whether None should be treated as valid.

    Returns:
        bool: True when the value is an int or float, or when None is allowed and provided.
    """
    if value is None:
        return allow_none

    return isinstance(value, (int, float)) and not isinstance(value, bool)


def is_non_negative_number(value: Any, allow_none: bool = False) -> bool:
    """
    Return whether a value is a numeric value greater than or equal to zero.

    Args:
        value (Any): Candidate value to check.
        allow_none (bool): Whether None should be treated as valid.

    Returns:
        bool: True when the value is a non-negative number, or when None is allowed and provided.
    """
    if value is None:
        return allow_none

    return is_number(value) and value >= 0


def is_port_number(value: Any, allow_none: bool = False) -> bool:
    """
    Return whether a value fits the TCP/UDP port range.

    Args:
        value (Any): Candidate value to check.
        allow_none (bool): Whether None should be treated as valid.

    Returns:
        bool: True when the value is an integer from 0 through 65535, or when None is allowed and provided.
    """
    if value is None:
        return allow_none

    return is_integer(value) and 0 <= value <= 65535


def is_http_status_code(value: Any, allow_none: bool = False) -> bool:
    """
    Return whether a value fits the HTTP status-code range.

    Args:
        value (Any): Candidate value to check.
        allow_none (bool): Whether None should be treated as valid.

    Returns:
        bool: True when the value is an integer from 100 through 599, or when None is allowed and provided.
    """
    if value is None:
        return allow_none

    return is_integer(value) and 100 <= value <= 599


def is_ip_address(value: Any, allow_none: bool = False) -> bool:
    """
    Return whether a value is a valid IPv4 or IPv6 address string.

    Args:
        value (Any): Candidate value to check.
        allow_none (bool): Whether None should be treated as valid.

    Returns:
        bool: True when the value is an IP address string, or when None is allowed and provided.
    """
    if value is None:
        return allow_none

    if not isinstance(value, str):
        return False

    try:
        ip_address(value)
    except ValueError:
        return False

    return True


def require_non_negative_integer(field_name: str, value: Any, allow_none: bool = False) -> None:
    """
    Raise ValueError unless a value is a non-negative integer.

    Args:
        field_name (str): Field name to include in validation errors.
        value (Any): Candidate value to validate.
        allow_none (bool): Whether None should be treated as valid.

    Returns:
        None: Raises ValueError when the value is invalid.
    """
    if not is_non_negative_integer(value, allow_none=allow_none):
        raise ValueError(f"{field_name} must be a non-negative integer")


def require_non_negative_number(field_name: str, value: Any, allow_none: bool = False) -> None:
    """
    Raise ValueError unless a value is a non-negative number.

    Args:
        field_name (str): Field name to include in validation errors.
        value (Any): Candidate value to validate.
        allow_none (bool): Whether None should be treated as valid.

    Returns:
        None: Raises ValueError when the value is invalid.
    """
    if not is_non_negative_number(value, allow_none=allow_none):
        raise ValueError(f"{field_name} must be a non-negative number")


def require_port_number(field_name: str, value: Any, allow_none: bool = False) -> None:
    """
    Raise ValueError unless a value fits the TCP/UDP port range.

    Args:
        field_name (str): Field name to include in validation errors.
        value (Any): Candidate value to validate.
        allow_none (bool): Whether None should be treated as valid.

    Returns:
        None: Raises ValueError when the value is invalid.
    """
    if not is_port_number(value, allow_none=allow_none):
        raise ValueError(f"{field_name} must be between 0 and 65535")


def require_ip_address(field_name: str, value: Any, allow_none: bool = False) -> None:
    """
    Raise ValueError unless a value is a valid IPv4 or IPv6 address string.

    Args:
        field_name (str): Field name to include in validation errors.
        value (Any): Candidate value to validate.
        allow_none (bool): Whether None should be treated as valid.

    Returns:
        None: Raises ValueError when the value is invalid.
    """
    if not is_ip_address(value, allow_none=allow_none):
        raise ValueError(f"{field_name} must be a valid IP address")


__all__ = [
    "is_http_status_code",
    "is_integer",
    "is_ip_address",
    "is_non_negative_integer",
    "is_non_negative_number",
    "is_number",
    "is_port_number",
    "require_ip_address",
    "require_non_negative_integer",
    "require_non_negative_number",
    "require_port_number",
]
