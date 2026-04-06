"""Tests for PaginatedReport."""

import unittest
from unittest.mock import Mock

from ssrs_library._paginated_report import PaginatedReport
from ssrs_library._datasource import DataSource
from ssrs_library._cache_refresh_plan import CacheRefreshPlan
from ssrs_library._schedule import Schedule

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
REPORT_DATA = {
    "Id": "rdl-1",
    "Name": "Monthly Invoices",
    "Path": "/Finance/Monthly Invoices",
    "Description": "Monthly invoice report",
    "HasDataSources": True,
}


def _report(data=None):
    return PaginatedReport(Mock(), data or REPORT_DATA)


# ---------------------------------------------------------------------------
# Properties
# ---------------------------------------------------------------------------
class TestProperties(unittest.TestCase):

    def setUp(self):
        self.r = _report()

    def test_id(self):
        self.assertEqual(self.r.id, "rdl-1")

    def test_name(self):
        self.assertEqual(self.r.name, "Monthly Invoices")

    def test_path(self):
        self.assertEqual(self.r.path, "/Finance/Monthly Invoices")

    def test_description(self):
        self.assertEqual(self.r.description, "Monthly invoice report")

    def test_has_data_sources_true(self):
        self.assertTrue(self.r.has_data_sources)

    def test_has_data_sources_missing_defaults_false(self):
        self.assertFalse(_report({"Id": "x", "Name": "X", "Path": "/X"}).has_data_sources)

    def test_description_missing_defaults_empty(self):
        self.assertEqual(_report({"Id": "x", "Name": "X", "Path": "/X"}).description, "")

    def test_repr_contains_name(self):
        self.assertIn("Monthly Invoices", repr(self.r))


# ---------------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------------
class TestDelete(unittest.TestCase):

    def test_calls_correct_endpoint(self):
        r = _report()
        r.delete()
        r._client._request.assert_called_once_with("DELETE", "Reports(rdl-1)")


# ---------------------------------------------------------------------------
# Data sources
# ---------------------------------------------------------------------------
class TestDataSources(unittest.TestCase):

    def setUp(self):
        self.r = _report()

    def _ds_payload(self, name="FinanceDB"):
        return {
            "Id": "ds-1", "Name": name,
            "ConnectionString": "Server=y;",
            "DataSourceType": "SQL",
            "Enabled": True,
            "CredentialRetrieval": "None",
        }

    def test_get_returns_datasource_objects(self):
        self.r._client._request.return_value = {"value": [self._ds_payload()]}
        sources = self.r.get_datasources()
        self.assertEqual(len(sources), 1)
        self.assertIsInstance(sources[0], DataSource)
        self.assertEqual(sources[0].name, "FinanceDB")

    def test_get_calls_correct_endpoint(self):
        self.r._client._request.return_value = {"value": []}
        self.r.get_datasources()
        self.r._client._request.assert_called_once_with(
            "GET", "Reports(rdl-1)/DataSources"
        )

    def test_set_serialises_and_puts(self):
        ds = DataSource("FinDB", "Server=y;")
        self.r.set_datasources([ds])
        self.r._client._request.assert_called_once_with(
            "PUT", "Reports(rdl-1)/DataSources", json=[ds.to_api()]
        )

    def test_set_multiple(self):
        sources = [DataSource("D1", "S=a;"), DataSource("D2", "S=b;")]
        self.r.set_datasources(sources)
        self.assertEqual(len(self.r._client._request.call_args[1]["json"]), 2)


# ---------------------------------------------------------------------------
# Parameters
# ---------------------------------------------------------------------------
class TestParameters(unittest.TestCase):

    def setUp(self):
        self.r = _report()

    def test_get_returns_list(self):
        params = [{"Name": "Year", "DefaultValue": "2025"}]
        self.r._client._request.return_value = {"value": params}
        self.assertEqual(self.r.get_parameters(), params)

    def test_get_calls_correct_endpoint(self):
        self.r._client._request.return_value = {"value": []}
        self.r.get_parameters()
        self.r._client._request.assert_called_once_with(
            "GET", "Reports(rdl-1)/ParameterDefinitions"
        )

    def test_get_empty(self):
        self.r._client._request.return_value = {"value": []}
        self.assertEqual(self.r.get_parameters(), [])

    def test_set_patches_definitions(self):
        params = [{"Name": "Year", "DefaultValue": "2025"}]
        self.r.set_parameters(params)
        self.r._client._request.assert_called_once_with(
            "PATCH", "Reports(rdl-1)/ParameterDefinitions", json=params
        )

    def test_set_multiple_params(self):
        params = [
            {"Name": "Year", "DefaultValue": "2025"},
            {"Name": "Region", "DefaultValue": "West"},
        ]
        self.r.set_parameters(params)
        payload = self.r._client._request.call_args[1]["json"]
        self.assertEqual(len(payload), 2)


# ---------------------------------------------------------------------------
# Cache refresh plans
# ---------------------------------------------------------------------------
class TestCacheRefreshPlans(unittest.TestCase):

    def setUp(self):
        self.r = _report()

    def _plan_data(self, pid="p-1"):
        return {"Id": pid, "Description": "Weekly", "EventType": "TimedSubscription"}

    def test_get_returns_plan_objects(self):
        self.r._client._request.return_value = {"value": [self._plan_data()]}
        plans = self.r.get_cache_refresh_plans()
        self.assertEqual(len(plans), 1)
        self.assertIsInstance(plans[0], CacheRefreshPlan)

    def test_get_calls_correct_endpoint(self):
        self.r._client._request.return_value = {"value": []}
        self.r.get_cache_refresh_plans()
        self.r._client._request.assert_called_once_with(
            "GET", "Reports(rdl-1)/CacheRefreshPlans"
        )

    def test_get_empty(self):
        self.r._client._request.return_value = {"value": []}
        self.assertEqual(self.r.get_cache_refresh_plans(), [])

    def test_create_with_schedule_object(self):
        self.r._client._request.return_value = self._plan_data("p-2")
        plan = self.r.create_cache_refresh_plan(
            description="Daily", schedule=Schedule.daily(hour=3)
        )
        self.assertIsInstance(plan, CacheRefreshPlan)
        payload = self.r._client._request.call_args[1]["json"]
        self.assertEqual(payload["CatalogItemPath"], "/Finance/Monthly Invoices")
        self.assertEqual(payload["EventType"], "TimedSubscription")
        self.assertIn("Schedule", payload)

    def test_create_without_schedule(self):
        self.r._client._request.return_value = self._plan_data()
        self.r.create_cache_refresh_plan(description="No schedule")
        payload = self.r._client._request.call_args[1]["json"]
        self.assertNotIn("Schedule", payload)
        self.assertEqual(payload["CatalogItemPath"], "/Finance/Monthly Invoices")

    def test_create_with_custom_event_type(self):
        self.r._client._request.return_value = self._plan_data()
        self.r.create_cache_refresh_plan(event_type="SnapshotUpdated")
        payload = self.r._client._request.call_args[1]["json"]
        self.assertEqual(payload["EventType"], "SnapshotUpdated")

    def test_create_posts_to_correct_endpoint(self):
        self.r._client._request.return_value = self._plan_data()
        self.r.create_cache_refresh_plan()
        method, endpoint = self.r._client._request.call_args[0]
        self.assertEqual(method, "POST")
        self.assertEqual(endpoint, "CacheRefreshPlans")


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
        self.r = _report()

    def test_calls_correct_endpoint(self):
        self.r._client._request.return_value = POLICIES_DATA
        self.r.get_policies()
        self.r._client._request.assert_called_once_with(
            "GET", "Reports(rdl-1)/Policies"
        )

    def test_returns_policy_dict(self):
        self.r._client._request.return_value = POLICIES_DATA
        result = self.r.get_policies()
        self.assertIn("InheritParentSecurity", result)
        self.assertIn("Policies", result)

    def test_returns_default_when_server_returns_none(self):
        self.r._client._request.return_value = None
        result = self.r.get_policies()
        self.assertFalse(result["InheritParentSecurity"])
        self.assertEqual(result["Policies"], [])

    def test_policies_list_length(self):
        self.r._client._request.return_value = POLICIES_DATA
        result = self.r.get_policies()
        self.assertEqual(len(result["Policies"]), 2)


class TestSetPolicies(unittest.TestCase):

    def test_calls_correct_endpoint(self):
        r = _report()
        r.set_policies(POLICIES_DATA)
        r._client._request.assert_called_once_with(
            "PUT", "Reports(rdl-1)/Policies", json=POLICIES_DATA
        )

    def test_sends_full_policy_dict(self):
        r = _report()
        r.set_policies(POLICIES_DATA)
        payload = r._client._request.call_args[1]["json"]
        self.assertIn("InheritParentSecurity", payload)
        self.assertIn("Policies", payload)


class TestAddUser(unittest.TestCase):

    def setUp(self):
        self.r = _report()

    def _setup_policies(self, policies=None):
        self.r._client._request.return_value = {
            "InheritParentSecurity": False,
            "Policies": policies or [],
        }

    def test_adds_new_user(self):
        self._setup_policies()
        self.r.add_user("CORP\\bob", ["Browser"])
        put_call = [c for c in self.r._client._request.call_args_list
                    if c[0][0] == "PUT"][0]
        policies = put_call[1]["json"]["Policies"]
        self.assertIn("CORP\\bob", [p["GroupUserName"] for p in policies])

    def test_new_user_roles_formatted_correctly(self):
        self._setup_policies()
        self.r.add_user("CORP\\bob", ["Browser"])
        put_call = [c for c in self.r._client._request.call_args_list
                    if c[0][0] == "PUT"][0]
        policies = put_call[1]["json"]["Policies"]
        bob = next(p for p in policies if p["GroupUserName"] == "CORP\\bob")
        self.assertEqual(bob["Roles"], [{"RoleName": "Browser"}])

    def test_merges_roles_for_existing_user(self):
        self._setup_policies([
            {"GroupUserName": "CORP\\alice", "Roles": [{"RoleName": "Browser"}]}
        ])
        self.r.add_user("CORP\\alice", ["Publisher"])
        put_call = [c for c in self.r._client._request.call_args_list
                    if c[0][0] == "PUT"][0]
        alice = next(p for p in put_call[1]["json"]["Policies"]
                     if p["GroupUserName"] == "CORP\\alice")
        role_names = {r["RoleName"] for r in alice["Roles"]}
        self.assertIn("Browser", role_names)
        self.assertIn("Publisher", role_names)

    def test_no_duplicate_roles(self):
        self._setup_policies([
            {"GroupUserName": "CORP\\alice", "Roles": [{"RoleName": "Browser"}]}
        ])
        self.r.add_user("CORP\\alice", ["Browser"])
        put_call = [c for c in self.r._client._request.call_args_list
                    if c[0][0] == "PUT"][0]
        alice = next(p for p in put_call[1]["json"]["Policies"]
                     if p["GroupUserName"] == "CORP\\alice")
        self.assertEqual(
            sum(1 for r in alice["Roles"] if r["RoleName"] == "Browser"), 1
        )

    def test_case_insensitive_username(self):
        self._setup_policies([
            {"GroupUserName": "CORP\\Alice", "Roles": [{"RoleName": "Browser"}]}
        ])
        self.r.add_user("corp\\alice", ["Publisher"])
        put_call = [c for c in self.r._client._request.call_args_list
                    if c[0][0] == "PUT"][0]
        self.assertEqual(len(put_call[1]["json"]["Policies"]), 1)

    def test_preserves_other_users(self):
        self._setup_policies([
            {"GroupUserName": "CORP\\alice", "Roles": [{"RoleName": "Browser"}]}
        ])
        self.r.add_user("CORP\\bob", ["Publisher"])
        put_call = [c for c in self.r._client._request.call_args_list
                    if c[0][0] == "PUT"][0]
        self.assertEqual(len(put_call[1]["json"]["Policies"]), 2)


class TestRemoveUser(unittest.TestCase):

    def setUp(self):
        self.r = _report()

    def _setup_policies(self, policies=None):
        self.r._client._request.return_value = {
            "InheritParentSecurity": False,
            "Policies": policies or [],
        }

    def test_removes_existing_user(self):
        self._setup_policies([
            {"GroupUserName": "CORP\\alice", "Roles": [{"RoleName": "Browser"}]},
            {"GroupUserName": "CORP\\bob",   "Roles": [{"RoleName": "Publisher"}]},
        ])
        self.r.remove_user("CORP\\alice")
        put_call = [c for c in self.r._client._request.call_args_list
                    if c[0][0] == "PUT"][0]
        usernames = [p["GroupUserName"] for p in put_call[1]["json"]["Policies"]]
        self.assertNotIn("CORP\\alice", usernames)
        self.assertIn("CORP\\bob", usernames)

    def test_noop_for_absent_user(self):
        self._setup_policies([
            {"GroupUserName": "CORP\\alice", "Roles": [{"RoleName": "Browser"}]}
        ])
        self.r.remove_user("CORP\\nobody")
        put_call = [c for c in self.r._client._request.call_args_list
                    if c[0][0] == "PUT"][0]
        self.assertEqual(len(put_call[1]["json"]["Policies"]), 1)

    def test_case_insensitive_removal(self):
        self._setup_policies([
            {"GroupUserName": "CORP\\Alice", "Roles": [{"RoleName": "Browser"}]}
        ])
        self.r.remove_user("corp\\alice")
        put_call = [c for c in self.r._client._request.call_args_list
                    if c[0][0] == "PUT"][0]
        self.assertEqual(put_call[1]["json"]["Policies"], [])

    def test_empty_policies_after_removing_last_user(self):
        self._setup_policies([
            {"GroupUserName": "CORP\\alice", "Roles": [{"RoleName": "Browser"}]}
        ])
        self.r.remove_user("CORP\\alice")
        put_call = [c for c in self.r._client._request.call_args_list
                    if c[0][0] == "PUT"][0]
        self.assertEqual(put_call[1]["json"]["Policies"], [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
