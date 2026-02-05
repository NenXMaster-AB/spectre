"""
Diff Detection

Compares current scan results with baseline to detect changes.
"""

from __future__ import annotations

from typing import Any

import structlog

from spectre.heartbeat.models import WatchResultChange, AlertSeverity

logger = structlog.get_logger(__name__)


def compute_diff(
    old_data: dict[str, Any],
    new_data: dict[str, Any],
    tracked_fields: list[str] | None = None,
) -> list[WatchResultChange]:
    """
    Compute differences between two data snapshots.

    Args:
        old_data: Previous snapshot
        new_data: Current snapshot
        tracked_fields: Specific fields to track (None = all)

    Returns:
        List of detected changes
    """
    changes: list[WatchResultChange] = []

    # Determine which fields to compare
    if tracked_fields:
        fields = set(tracked_fields)
    else:
        fields = set(old_data.keys()) | set(new_data.keys())

    for field in fields:
        old_value = old_data.get(field)
        new_value = new_data.get(field)

        if old_value == new_value:
            continue

        # Determine change type and severity
        if old_value is None and new_value is not None:
            change = WatchResultChange(
                field=field,
                change_type="added",
                old_value=None,
                new_value=new_value,
                severity=_assess_severity(field, "added", new_value),
            )
        elif old_value is not None and new_value is None:
            change = WatchResultChange(
                field=field,
                change_type="removed",
                old_value=old_value,
                new_value=None,
                severity=_assess_severity(field, "removed", old_value),
            )
        else:
            # Both have values - check for list/set differences
            if isinstance(old_value, list) and isinstance(new_value, list):
                list_changes = _compare_lists(field, old_value, new_value)
                changes.extend(list_changes)
                continue
            elif isinstance(old_value, dict) and isinstance(new_value, dict):
                # Recurse into nested dicts
                nested_changes = compute_diff(old_value, new_value)
                for nc in nested_changes:
                    nc.field = f"{field}.{nc.field}"
                    changes.append(nc)
                continue
            else:
                change = WatchResultChange(
                    field=field,
                    change_type="modified",
                    old_value=old_value,
                    new_value=new_value,
                    severity=_assess_severity(field, "modified", new_value),
                )

        changes.append(change)

    return changes


def _compare_lists(
    field: str,
    old_list: list[Any],
    new_list: list[Any],
) -> list[WatchResultChange]:
    """Compare two lists and return changes."""
    changes: list[WatchResultChange] = []

    # Convert to sets for comparison (if items are hashable)
    try:
        old_set = set(_normalize_item(item) for item in old_list)
        new_set = set(_normalize_item(item) for item in new_list)

        added = new_set - old_set
        removed = old_set - new_set

        if added:
            changes.append(WatchResultChange(
                field=f"{field}",
                change_type="added",
                old_value=None,
                new_value=list(added),
                severity=_assess_severity(field, "added", list(added)),
            ))

        if removed:
            changes.append(WatchResultChange(
                field=f"{field}",
                change_type="removed",
                old_value=list(removed),
                new_value=None,
                severity=_assess_severity(field, "removed", list(removed)),
            ))

    except (TypeError, ValueError):
        # Items not hashable, do simple length comparison
        if len(old_list) != len(new_list):
            changes.append(WatchResultChange(
                field=field,
                change_type="modified",
                old_value=f"[{len(old_list)} items]",
                new_value=f"[{len(new_list)} items]",
                severity=AlertSeverity.LOW,
            ))

    return changes


def _normalize_item(item: Any) -> Any:
    """Normalize an item for set comparison."""
    if isinstance(item, dict):
        # Convert dict to frozenset of items for hashability
        return frozenset(
            (k, _normalize_item(v)) for k, v in sorted(item.items())
        )
    elif isinstance(item, list):
        return tuple(_normalize_item(i) for i in item)
    return item


def _assess_severity(
    field: str,
    change_type: str,
    value: Any,
) -> AlertSeverity:
    """
    Assess the severity of a change based on the field and change type.

    This uses heuristics based on common OSINT/threat intel field names.
    """
    field_lower = field.lower()

    # High severity indicators
    high_severity_fields = {
        "malicious", "threat", "malware", "c2", "c&c", "ioc",
        "indicator", "attack", "exploit", "vulnerability", "cve",
        "compromised", "phishing", "spam", "botnet",
    }

    # Medium severity indicators
    medium_severity_fields = {
        "subdomain", "dns", "certificate", "ssl", "tls",
        "ip_address", "nameserver", "mx_record", "port",
        "service", "technology", "whois",
    }

    # Check for high severity
    for indicator in high_severity_fields:
        if indicator in field_lower:
            if change_type == "added":
                return AlertSeverity.HIGH
            return AlertSeverity.MEDIUM

    # Check for medium severity
    for indicator in medium_severity_fields:
        if indicator in field_lower:
            if change_type == "added":
                return AlertSeverity.MEDIUM
            return AlertSeverity.LOW

    # New items are generally more interesting than removed
    if change_type == "added":
        return AlertSeverity.LOW

    return AlertSeverity.INFO


def check_conditions(
    data: dict[str, Any],
    conditions: list[dict[str, Any]],
) -> list[tuple[dict[str, Any], bool, Any]]:
    """
    Check conditions against data.

    Args:
        data: Data to check
        conditions: List of condition dicts with field, operator, value

    Returns:
        List of (condition, matched, actual_value) tuples
    """
    results = []

    for condition in conditions:
        field = condition.get("field", "")
        operator = condition.get("operator", "eq")
        expected = condition.get("value")

        # Get the actual value (supports dot notation)
        actual = _get_nested_value(data, field)

        matched = _evaluate_condition(actual, operator, expected)
        results.append((condition, matched, actual))

    return results


def _get_nested_value(data: dict[str, Any], field: str) -> Any:
    """Get a value from nested dict using dot notation."""
    parts = field.split(".")
    value = data

    for part in parts:
        if isinstance(value, dict):
            value = value.get(part)
        elif isinstance(value, list) and part.isdigit():
            idx = int(part)
            value = value[idx] if idx < len(value) else None
        else:
            return None

    return value


def _evaluate_condition(
    actual: Any,
    operator: str,
    expected: Any,
) -> bool:
    """Evaluate a single condition."""
    if operator == "eq":
        return actual == expected
    elif operator == "ne":
        return actual != expected
    elif operator == "gt":
        return actual is not None and actual > expected
    elif operator == "lt":
        return actual is not None and actual < expected
    elif operator == "gte":
        return actual is not None and actual >= expected
    elif operator == "lte":
        return actual is not None and actual <= expected
    elif operator == "contains":
        if isinstance(actual, str):
            return expected in actual
        elif isinstance(actual, (list, set)):
            return expected in actual
        return False
    elif operator == "not_contains":
        if isinstance(actual, str):
            return expected not in actual
        elif isinstance(actual, (list, set)):
            return expected not in actual
        return True
    elif operator == "exists":
        return actual is not None
    elif operator == "not_exists":
        return actual is None
    elif operator == "in":
        return actual in expected if expected else False
    elif operator == "not_in":
        return actual not in expected if expected else True
    elif operator == "regex":
        import re
        return bool(re.search(expected, str(actual))) if actual else False
    else:
        logger.warning("Unknown operator", operator=operator)
        return False
