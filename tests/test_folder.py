"""Tests for Folder."""

import unittest
from unittest.mock import Mock

from ssrs_library._folder import Folder
from ssrs_library._powerbi_report import PowerBIReport
from ssrs_library._paginated_report import PaginatedReport

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
FOLDER_DATA = {
    "Id": "f-1",
    "Name": "Sales",
    "Path": "/Sales",
    "Description": "Sales folder",
}


def _folder(data=None):
    return Folder(Mock(), data or FOLDER_DATA)


# ---------------------------------------------------------------------------
# Properties
# ---------------------------------------------------------------------------
class TestProperties(unittest.TestCase):

    def setUp(self):
        self.f = _folder()

    def test_id(self):
        self.assertEqual(self.f.id, "f-1")

    def test_name(self):
        self.assertEqual(self.f.name, "Sales")

    def test_path(self):
        self.assertEqual(self.f.path, "/Sales")

    def test_description(self):
        self.assertEqual(self.f.description, "Sales folder")

    def test_description_missing_defaults_empty(self):
        self.assertEqual(
            _folder({"Id": "x", "Name": "X", "Path": "/X"}).description, ""
        )

    def test_repr_contains_name(self):
        self.assertIn("Sales", repr(self.f))

    def test_repr_contains_path(self):
        self.assertIn("/Sales", repr(self.f))


# ---------------------------------------------------------------------------
# list_items
# ---------------------------------------------------------------------------
class TestListItems(unittest.TestCase):

    def setUp(self):
        self.f = _folder()

    def test_returns_raw_items(self):
        items = [
            {"Id": "r-1", "Name": "Report", "Type": "PowerBIReport"},
            {"Id": "f-2", "Name": "SubFolder", "Type": "Folder"},
        ]
        self.f._client._request.return_value = {"value": items}
        result = self.f.list_items()
        self.assertEqual(result, items)

    def test_calls_catalog_items_endpoint(self):
        self.f._client._request.return_value = {"value": []}
        self.f.list_items()
        self.f._client._request.assert_called_once_with(
            "GET", "Folders(f-1)/CatalogItems"
        )

    def test_empty_folder(self):
        self.f._client._request.return_value = {"value": []}
        self.assertEqual(self.f.list_items(), [])

    def test_mixed_types_all_returned(self):
        items = [
            {"Id": "a", "Type": "PowerBIReport"},
            {"Id": "b", "Type": "Report"},
            {"Id": "c", "Type": "Folder"},
            {"Id": "d", "Type": "DataSource"},
        ]
        self.f._client._request.return_value = {"value": items}
        self.assertEqual(len(self.f.list_items()), 4)


# ---------------------------------------------------------------------------
# list_powerbi_reports
# ---------------------------------------------------------------------------
class TestListPowerBIReports(unittest.TestCase):

    def test_delegates_to_client_with_path(self):
        f = _folder()
        expected = [Mock(spec=PowerBIReport)]
        f._client.list_powerbi_reports.return_value = expected
        result = f.list_powerbi_reports()
        self.assertEqual(result, expected)
        f._client.list_powerbi_reports.assert_called_once_with("/Sales")

    def test_uses_folder_path(self):
        f = _folder({**FOLDER_DATA, "Path": "/Deep/Nested"})
        f._client.list_powerbi_reports.return_value = []
        f.list_powerbi_reports()
        f._client.list_powerbi_reports.assert_called_once_with("/Deep/Nested")


# ---------------------------------------------------------------------------
# list_paginated_reports
# ---------------------------------------------------------------------------
class TestListPaginatedReports(unittest.TestCase):

    def test_delegates_to_client_with_path(self):
        f = _folder()
        expected = [Mock(spec=PaginatedReport)]
        f._client.list_paginated_reports.return_value = expected
        result = f.list_paginated_reports()
        self.assertEqual(result, expected)
        f._client.list_paginated_reports.assert_called_once_with("/Sales")


# ---------------------------------------------------------------------------
# list_folders
# ---------------------------------------------------------------------------
class TestListFolders(unittest.TestCase):

    def test_delegates_to_client_with_path(self):
        f = _folder()
        expected = [Mock(spec=Folder)]
        f._client.list_folders.return_value = expected
        result = f.list_folders()
        self.assertEqual(result, expected)
        f._client.list_folders.assert_called_once_with("/Sales")


# ---------------------------------------------------------------------------
# delete
# ---------------------------------------------------------------------------
class TestDelete(unittest.TestCase):

    def test_calls_correct_endpoint(self):
        f = _folder()
        f.delete()
        f._client._request.assert_called_once_with("DELETE", "Folders(f-1)")


# ---------------------------------------------------------------------------
# Security policies
# ---------------------------------------------------------------------------
POLICIES_DATA = {
    "InheritParentSecurity": False,
    "Policies": [
        {"GroupUserName": "CORP\\alice", "Roles": [{"RoleName": "Browser"}]},
        {"GroupUserName": "CORP\\admins", "Roles": [{"RoleName": "Content Manager"}]},
    ],
}


class TestGetPolicies(unittest.TestCase):

    def setUp(self):
        self.f = _folder()

    def test_calls_correct_endpoint(self):
        self.f._client._request.return_value = POLICIES_DATA
        self.f.get_policies()
        self.f._client._request.assert_called_once_with("GET", "Folders(f-1)/Policies")

    def test_returns_policy_dict(self):
        self.f._client._request.return_value = POLICIES_DATA
        result = self.f.get_policies()
        self.assertIn("InheritParentSecurity", result)
        self.assertIn("Policies", result)

    def test_returns_default_when_server_returns_none(self):
        self.f._client._request.return_value = None
        result = self.f.get_policies()
        self.assertFalse(result["InheritParentSecurity"])
        self.assertEqual(result["Policies"], [])

    def test_inherit_parent_security_value(self):
        self.f._client._request.return_value = POLICIES_DATA
        result = self.f.get_policies()
        self.assertFalse(result["InheritParentSecurity"])

    def test_policies_list_length(self):
        self.f._client._request.return_value = POLICIES_DATA
        result = self.f.get_policies()
        self.assertEqual(len(result["Policies"]), 2)


class TestSetPolicies(unittest.TestCase):

    def test_calls_correct_endpoint(self):
        f = _folder()
        f.set_policies(POLICIES_DATA)
        f._client._request.assert_called_once_with(
            "PUT", "Folders(f-1)/Policies", json=POLICIES_DATA
        )

    def test_sends_full_policy_dict(self):
        f = _folder()
        f.set_policies(POLICIES_DATA)
        payload = f._client._request.call_args[1]["json"]
        self.assertIn("InheritParentSecurity", payload)
        self.assertIn("Policies", payload)


class TestAddUser(unittest.TestCase):

    def setUp(self):
        self.f = _folder()

    def _setup_policies(self, policies=None):
        data = {
            "InheritParentSecurity": False,
            "Policies": policies or [],
        }
        self.f._client._request.return_value = data

    def test_adds_new_user(self):
        self._setup_policies()
        self.f.add_user("CORP\\bob", ["Browser"])
        put_call = [
            c for c in self.f._client._request.call_args_list if c[0][0] == "PUT"
        ][0]
        policies = put_call[1]["json"]["Policies"]
        usernames = [p["GroupUserName"] for p in policies]
        self.assertIn("CORP\\bob", usernames)

    def test_new_user_gets_correct_roles(self):
        self._setup_policies()
        self.f.add_user("CORP\\bob", ["Browser"])
        put_call = [
            c for c in self.f._client._request.call_args_list if c[0][0] == "PUT"
        ][0]
        policies = put_call[1]["json"]["Policies"]
        bob = next(p for p in policies if p["GroupUserName"] == "CORP\\bob")
        role_names = [r["RoleName"] for r in bob["Roles"]]
        self.assertIn("Browser", role_names)

    def test_merges_roles_for_existing_user(self):
        self._setup_policies(
            [{"GroupUserName": "CORP\\alice", "Roles": [{"RoleName": "Browser"}]}]
        )
        self.f.add_user("CORP\\alice", ["Publisher"])
        put_call = [
            c for c in self.f._client._request.call_args_list if c[0][0] == "PUT"
        ][0]
        policies = put_call[1]["json"]["Policies"]
        alice = next(p for p in policies if p["GroupUserName"] == "CORP\\alice")
        role_names = {r["RoleName"] for r in alice["Roles"]}
        self.assertIn("Browser", role_names)
        self.assertIn("Publisher", role_names)

    def test_no_duplicate_roles_on_merge(self):
        self._setup_policies(
            [{"GroupUserName": "CORP\\alice", "Roles": [{"RoleName": "Browser"}]}]
        )
        self.f.add_user("CORP\\alice", ["Browser"])
        put_call = [
            c for c in self.f._client._request.call_args_list if c[0][0] == "PUT"
        ][0]
        policies = put_call[1]["json"]["Policies"]
        alice = next(p for p in policies if p["GroupUserName"] == "CORP\\alice")
        browser_count = sum(1 for r in alice["Roles"] if r["RoleName"] == "Browser")
        self.assertEqual(browser_count, 1)

    def test_case_insensitive_username_matching(self):
        self._setup_policies(
            [{"GroupUserName": "CORP\\Alice", "Roles": [{"RoleName": "Browser"}]}]
        )
        self.f.add_user("corp\\alice", ["Publisher"])
        put_call = [
            c for c in self.f._client._request.call_args_list if c[0][0] == "PUT"
        ][0]
        policies = put_call[1]["json"]["Policies"]
        # Should have updated the existing entry, not created a new one
        self.assertEqual(len(policies), 1)

    def test_preserves_other_users(self):
        self._setup_policies(
            [{"GroupUserName": "CORP\\alice", "Roles": [{"RoleName": "Browser"}]}]
        )
        self.f.add_user("CORP\\bob", ["Publisher"])
        put_call = [
            c for c in self.f._client._request.call_args_list if c[0][0] == "PUT"
        ][0]
        policies = put_call[1]["json"]["Policies"]
        self.assertEqual(len(policies), 2)


class TestRemoveUser(unittest.TestCase):

    def setUp(self):
        self.f = _folder()

    def _setup_policies(self, policies=None):
        data = {
            "InheritParentSecurity": False,
            "Policies": policies or [],
        }
        self.f._client._request.return_value = data

    def test_removes_existing_user(self):
        self._setup_policies(
            [
                {"GroupUserName": "CORP\\alice", "Roles": [{"RoleName": "Browser"}]},
                {"GroupUserName": "CORP\\bob", "Roles": [{"RoleName": "Publisher"}]},
            ]
        )
        self.f.remove_user("CORP\\alice")
        put_call = [
            c for c in self.f._client._request.call_args_list if c[0][0] == "PUT"
        ][0]
        policies = put_call[1]["json"]["Policies"]
        usernames = [p["GroupUserName"] for p in policies]
        self.assertNotIn("CORP\\alice", usernames)
        self.assertIn("CORP\\bob", usernames)

    def test_noop_for_absent_user(self):
        self._setup_policies(
            [{"GroupUserName": "CORP\\alice", "Roles": [{"RoleName": "Browser"}]}]
        )
        self.f.remove_user("CORP\\nobody")
        put_call = [
            c for c in self.f._client._request.call_args_list if c[0][0] == "PUT"
        ][0]
        policies = put_call[1]["json"]["Policies"]
        self.assertEqual(len(policies), 1)

    def test_case_insensitive_removal(self):
        self._setup_policies(
            [{"GroupUserName": "CORP\\Alice", "Roles": [{"RoleName": "Browser"}]}]
        )
        self.f.remove_user("corp\\alice")
        put_call = [
            c for c in self.f._client._request.call_args_list if c[0][0] == "PUT"
        ][0]
        policies = put_call[1]["json"]["Policies"]
        self.assertEqual(len(policies), 0)

    def test_empty_policies_after_removing_last_user(self):
        self._setup_policies(
            [{"GroupUserName": "CORP\\alice", "Roles": [{"RoleName": "Browser"}]}]
        )
        self.f.remove_user("CORP\\alice")
        put_call = [
            c for c in self.f._client._request.call_args_list if c[0][0] == "PUT"
        ][0]
        self.assertEqual(put_call[1]["json"]["Policies"], [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
