"""Functional and access-control tests for ``json_search``."""

import unittest

from policy import POLICY
from recursive_json_search import json_search
from test_data import data, key1


class json_search_test(unittest.TestCase):
    def test_search_found(self):
        """A viewer can find a public issue summary nested in the sample data."""
        self.assertEqual(
            json_search(key1, data, role="viewer"),
            ["Network Device 10.10.20.82 Is Unreachable From Controller"],
        )

    def test_search_not_found(self):
        """A search for a key absent from the document returns an empty list."""
        self.assertEqual(json_search("doesNotExist", data, role="viewer"), [])

    def test_is_a_list(self):
        """The search API always represents results as a list."""
        self.assertIsInstance(json_search("status", data, role="viewer"), list)

    def test_search_aggregates_nested_matches(self):
        """Matches from nested dictionaries and lists are all retained."""
        nested = {
            "items": [
                {"target": "first", "children": [{"target": "second"}]},
                {"target": "third"},
            ]
        }
        self.assertEqual(
            json_search("target", nested, role="viewer"),
            ["first", "second", "third"],
        )

    def test_api_key_requires_admin(self):
        """Only admin may retrieve the policy-protected API key."""
        self.assertEqual(json_search("apiKey", data, role="viewer"), [])
        self.assertEqual(json_search("apiKey", data, role="operator"), [])
        self.assertEqual(
            json_search("apiKey", data, role="admin"),
            ["SNMP-COMMUNITY-STRING-7f3a9c"],
        )

    def test_management_ip_allows_operator_but_not_viewer(self):
        """Management IP access follows the admin/operator policy entry."""
        self.assertEqual(
            json_search("managementIpAddress", data, role="viewer"), []
        )
        self.assertEqual(
            json_search("managementIpAddress", data, role="operator"),
            ["10.10.20.21"],
        )

    def test_issue_summary_is_allowed_by_policy(self):
        """All roles listed by policy can read the public issue summary."""
        expected = [
            "Network Device 10.10.20.82 Is Unreachable From Controller"
        ]
        for role in POLICY["issueSummary"]:
            with self.subTest(role=role):
                self.assertEqual(json_search("issueSummary", data, role=role), expected)

    def test_invalid_or_missing_role_is_denied(self):
        """Unknown and missing roles cannot read even public fields."""
        self.assertEqual(json_search("status", data), [])
        self.assertEqual(json_search("status", data, role="unknown"), [])

    def test_disallowed_nested_fields_are_filtered_from_container_matches(self):
        """A public container match does not expose restricted descendants."""
        result = json_search("deviceDetails", data, role="viewer")
        self.assertEqual(len(result), 1)
        self.assertNotIn("apiKey", result[0])
        self.assertNotIn("managementIpAddress", result[0])


if __name__ == "__main__":
    unittest.main()
