"""Role-aware recursive search for JSON-like Python data."""

from policy import POLICY


VALID_ROLES = frozenset({"admin", "operator", "viewer"})


def _is_allowed(key, role):
    """Return whether ``role`` may read ``key`` under the configured policy."""
    if not isinstance(role, str) or role not in VALID_ROLES:
        return False
    if not isinstance(key, str):
        return False
    # Fields without an explicit policy entry are public to valid roles.
    return key not in POLICY or role in POLICY[key]


def _filter_value(value, role):
    """Remove policy-protected descendants the current role cannot read."""
    if isinstance(value, dict):
        filtered = {}
        for child_key, child_value in value.items():
            if _is_allowed(child_key, role):
                filtered[child_key] = _filter_value(child_value, role)
        return filtered
    if isinstance(value, list):
        return [_filter_value(item, role) for item in value]
    return value


def json_search(key, input_object, role=None):
    """Find all values associated with ``key`` in nested dictionaries/lists.

    Results are returned as a list in traversal order. Invalid or missing roles
    are denied, and a key restricted by ``policy.POLICY`` produces no results
    for roles that are not allowed to read it.
    """
    if not isinstance(role, str) or role not in VALID_ROLES:
        return []
    if not _is_allowed(key, role):
        return []

    results = []
    if isinstance(input_object, dict):
        for current_key, value in input_object.items():
            if current_key == key:
                results.append(_filter_value(value, role))
            # Keep walking even when this node matches: nested occurrences
            # belong in the aggregate result too.
            results.extend(json_search(key, value, role=role))
    elif isinstance(input_object, list):
        for item in input_object:
            results.extend(json_search(key, item, role=role))
    return results
