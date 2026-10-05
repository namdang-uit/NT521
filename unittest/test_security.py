import unittest

from recursive_json_search import json_search
from test_data import data


class JsonSearchSecurityTest(unittest.TestCase):
    def test_viewer_cannot_read_api_key(self):
        self.assertEqual([], json_search("apiKey", data, role="viewer"))

    def test_operator_cannot_read_api_key(self):
        self.assertEqual([], json_search("apiKey", data, role="operator"))

    def test_invalid_role_is_rejected(self):
        with self.assertRaises(ValueError):
            json_search("issueSummary", data, role="unknown")


if __name__ == "__main__":
    unittest.main()