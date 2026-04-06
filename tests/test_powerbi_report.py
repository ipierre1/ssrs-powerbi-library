"""Tests for PowerBIReport."""

import unittest
from unittest.mock import Mock

from ssrs_library._powerbi_report import PowerBIReport
from ssrs_library._datasource import DataSource
from ssrs_library._cache_refresh_plan import CacheRefreshPlan
from ssrs_library._schedule import Schedule

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
REPORT_DATA = {
    "Id": "r-1",
    "Name": "Revenue Q1",
    "Path": "/Sales/Revenue Q1",
    "Description": "Quarterly revenue",
    "HasDataSources": True,
}


def _report(data=None):
    return PowerBIReport(Mock(), data or REPORT_DATA)


# ---------------------------------------------------------------------------
# Properties
# ---------------------------------------------------------------------------
class TestProperties(unittest.TestCase):

    def setUp(self):
        self.r = _report()

    def test_id(self):
        self.assertEqual(self.r.id, "r-1")

    def test_name(self):
        self.assertEqual(self.r.name, "Revenue Q1")

    def test_path(self):
        self.assertEqual(self.r.path, "/Sales/Revenue Q1")

    def test_description(self):
        self.assertEqual(self.r.description, "Quarterly revenue")

    def test_has_data_sources_true(self):
        self.assertTrue(self.r.has_data_sources)

    def test_has_data_sources_missing_defaults_false(self):
        self.assertFalse(_report({"Id": "x", "Name": "X", "Path": "/X"}).has_data_sources)

    def test_description_missing_defaults_empty(self):
        self.assertEqual(_report({"Id": "x", "Name": "X", "Path": "/X"}).description, "")

    def test_repr_contains_name(self):
        self.assertIn("Revenue Q1", repr(self.r))

    def test_repr_contains_path(self):
        self.assertIn("/Sales/Revenue Q1", repr(self.r))


# ---------------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------------
class TestDelete(unittest.TestCase):

    def test_calls_correct_endpoint(self):
        r = _report()
        r.delete()
        r._client._request.assert_called_once_with("DELETE", "PowerBIReports(r-1)")


# ---------------------------------------------------------------------------
# Data sources
# ---------------------------------------------------------------------------
class TestDataSources(unittest.TestCase):

    def setUp(self):
        self.r = _report()

    def _ds_payload(self, name="SalesDB"):
        return {
            "Id": "ds-1", "Name": name,
            "ConnectionString": "Server=x;",
            "DataSourceType": "SQL",
            "Enabled": True,
            "CredentialRetrieval": "None",
        }

    def test_get_returns_datasource_objects(self):
        self.r._client._request.return_value = {"value": [self._ds_payload()]}
        sources = self.r.get_datasources()
        self.assertEqual(len(sources), 1)
        self.assertIsInstance(sources[0], DataSource)
        self.assertEqual(sources[0].name, "SalesDB")

    def test_get_calls_correct_endpoint(self):
        self.r._client._request.return_value = {"value": []}
        self.r.get_datasources()
        self.r._client._request.assert_called_once_with(
            "GET", "PowerBIReports(r-1)/DataSources"
        )

    def test_get_empty_response(self):
        self.r._client._request.return_value = {"value": []}
        self.assertEqual(self.r.get_datasources(), [])

    def test_set_serialises_and_puts(self):
        ds = DataSource("MyDB", "Server=x;")
        self.r.set_datasources([ds])
        self.r._client._request.assert_called_once_with(
            "PUT", "PowerBIReports(r-1)/DataSources", json=[ds.to_api()]
        )

    def test_set_multiple_datasources(self):
        ds1 = DataSource("DB1", "Server=a;")
        ds2 = DataSource("DB2", "Server=b;")
        self.r.set_datasources([ds1, ds2])
        payload = self.r._client._request.call_args[1]["json"]
        self.assertEqual(len(payload), 2)

    def test_set_empty_list(self):
        self.r.set_datasources([])
        payload = self.r._client._request.call_args[1]["json"]
        self.assertEqual(payload, [])


# ---------------------------------------------------------------------------
# Data model parameters
# ---------------------------------------------------------------------------
class TestDataModelParameters(unittest.TestCase):

    def setUp(self):
        self.r = _report()

    def test_get_returns_list(self):
        params = [{"Name": "Env", "Value": "Prod"}]
        self.r._client._request.return_value = {"value": params}
        self.assertEqual(self.r.get_data_model_parameters(), params)

    def test_get_calls_correct_endpoint(self):
        self.r._client._request.return_value = {"value": []}
        self.r.get_data_model_parameters()
        self.r._client._request.assert_called_once_with(
            "GET", "PowerBIReports(r-1)/DataModelParameters"
        )

    def test_get_empty(self):
        self.r._client._request.return_value = {"value": []}
        self.assertEqual(self.r.get_data_model_parameters(), [])

    def test_set_puts_params(self):
        params = [
            {"Name": "Env", "Value": "Prod"},
            {"Name": "Year", "Value": "2025"},
        ]
        self.r.set_data_model_parameters(params)
        self.r._client._request.assert_called_once_with(
            "PUT", "PowerBIReports(r-1)/DataModelParameters", json=params
        )


# ---------------------------------------------------------------------------
# Cache refresh plans
# ---------------------------------------------------------------------------
class TestCacheRefreshPlans(unittest.TestCase):

    def setUp(self):
        self.r = _report()

    def _plan_data(self, pid="p-1"):
        return {"Id": pid, "Description": "Daily", "EventType": "DataModelRefresh"}

    def test_get_returns_plan_objects(self):
        self.r._client._request.return_value = {"value": [self._plan_data()]}
        plans = self.r.get_cache_refresh_plans()
        self.assertEqual(len(plans), 1)
        self.assertIsInstance(plans[0], CacheRefreshPlan)
        self.assertEqual(plans[0].id, "p-1")

    def test_get_calls_correct_endpoint(self):
        self.r._client._request.return_value = {"value": []}
        self.r.get_cache_refresh_plans()
        self.r._client._request.assert_called_once_with(
            "GET", "PowerBIReports(r-1)/CacheRefreshPlans"
        )

    def test_get_empty(self):
        self.r._client._request.return_value = {"value": []}
        self.assertEqual(self.r.get_cache_refresh_plans(), [])

    def test_create_with_schedule_object_builds_correct_payload(self):
        self.r._client._request.return_value = self._plan_data("p-2")
        plan = self.r.create_cache_refresh_plan(
            description="Nightly",
            schedule=Schedule.daily(hour=2),
        )
        self.assertIsInstance(plan, CacheRefreshPlan)
        payload = self.r._client._request.call_args[1]["json"]
        self.assertEqual(payload["CatalogItemPath"], "/Sales/Revenue Q1")
        self.assertEqual(payload["EventType"], "DataModelRefresh")
        self.assertEqual(payload["Description"], "Nightly")
        self.assertIn("Schedule", payload)
        self.assertIn("Definition", payload["Schedule"])
        rec = payload["Schedule"]["Definition"]["Recurrence"]
        self.assertIn("DailyRecurrence", rec)

    def test_create_with_weekly_schedule(self):
        self.r._client._request.return_value = self._plan_data()
        self.r.create_cache_refresh_plan(
            schedule=Schedule.weekly(["Monday", "Friday"], hour=8),
        )
        rec = (self.r._client._request.call_args[1]["json"]
               ["Schedule"]["Definition"]["Recurrence"])
        self.assertIn("WeeklyRecurrence", rec)
        self.assertTrue(rec["WeeklyRecurrence"]["DaysOfWeek"]["Monday"])
        self.assertTrue(rec["WeeklyRecurrence"]["DaysOfWeek"]["Friday"])

    def test_create_with_monthly_schedule(self):
        self.r._client._request.return_value = self._plan_data()
        self.r.create_cache_refresh_plan(
            schedule=Schedule.monthly(day=1, hour=3),
        )
        rec = (self.r._client._request.call_args[1]["json"]
               ["Schedule"]["Definition"]["Recurrence"])
        self.assertIn("MonthlyRecurrence", rec)
        self.assertEqual(rec["MonthlyRecurrence"]["Days"], "1")

    def test_create_with_raw_dict(self):
        self.r._client._request.return_value = self._plan_data()
        raw = {"Definition": {"StartDateTime": "2025-01-01T00:00:00"}}
        self.r.create_cache_refresh_plan(schedule=raw)
        payload = self.r._client._request.call_args[1]["json"]
        self.assertEqual(payload["Schedule"], raw)

    def test_create_without_schedule(self):
        self.r._client._request.return_value = self._plan_data()
        self.r.create_cache_refresh_plan()
        payload = self.r._client._request.call_args[1]["json"]
        self.assertNotIn("Schedule", payload)
        # Still sets path and event type
        self.assertEqual(payload["CatalogItemPath"], "/Sales/Revenue Q1")
        self.assertEqual(payload["EventType"], "DataModelRefresh")

    def test_create_posts_to_correct_endpoint(self):
        self.r._client._request.return_value = self._plan_data()
        self.r.create_cache_refresh_plan()
        method, endpoint = self.r._client._request.call_args[0]
        self.assertEqual(method, "POST")
        self.assertEqual(endpoint, "CacheRefreshPlans")


# ---------------------------------------------------------------------------
# Row-level security
# ---------------------------------------------------------------------------
class TestRLS(unittest.TestCase):

    def setUp(self):
        self.r = _report()

    def test_get_roles_returns_list(self):
        roles = [
            {"ModelRoleName": "Region_West", "ModelRoleId": "role-1"},
            {"ModelRoleName": "Region_East", "ModelRoleId": "role-2"},
        ]
        self.r._client._request.return_value = {"value": roles}
        self.assertEqual(self.r.get_data_model_roles(), roles)

    def test_get_roles_calls_correct_endpoint(self):
        self.r._client._request.return_value = {"value": []}
        self.r.get_data_model_roles()
        self.r._client._request.assert_called_once_with(
            "GET", "PowerBIReports(r-1)/DataModelRoles"
        )

    def test_get_role_assignments(self):
        assignments = [{"GroupUserName": "CORP\\alice", "Roles": ["Region_West"]}]
        self.r._client._request.return_value = {"value": assignments}
        self.assertEqual(self.r.get_data_model_role_assignments(), assignments)

    def test_get_role_assignments_calls_correct_endpoint(self):
        self.r._client._request.return_value = {"value": []}
        self.r.get_data_model_role_assignments()
        self.r._client._request.assert_called_once_with(
            "GET", "PowerBIReports(r-1)/DataModelRoleAssignments"
        )

    def test_set_role_assignments(self):
        assignments = [
            {"GroupUserName": "CORP\\alice", "Roles": ["Region_West"]},
            {"GroupUserName": "CORP\\bob",   "Roles": ["Region_East"]},
        ]
        self.r.set_data_model_role_assignments(assignments)
        self.r._client._request.assert_called_once_with(
            "PUT",
            "PowerBIReports(r-1)/DataModelRoleAssignments",
            json=assignments,
        )

    def test_set_role_assignments_empty(self):
        self.r.set_data_model_role_assignments([])
        payload = self.r._client._request.call_args[1]["json"]
        self.assertEqual(payload, [])


# ---------------------------------------------------------------------------
# Catalog security policies
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
            "GET", "PowerBIReports(r-1)/Policies"
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


class TestSetPolicies(unittest.TestCase):

    def test_calls_correct_endpoint(self):
        r = _report()
        r.set_policies(POLICIES_DATA)
        r._client._request.assert_called_once_with(
            "PUT", "PowerBIReports(r-1)/Policies", json=POLICIES_DATA
        )


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
        # Should update existing entry rather than add a new one
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


# ---------------------------------------------------------------------------
# RLS convenience helpers
# ---------------------------------------------------------------------------
class TestAddRlsUser(unittest.TestCase):

    def setUp(self):
        self.r = _report()

    def _setup_assignments(self, assignments=None):
        self.r._client._request.return_value = {"value": assignments or []}

    def test_adds_new_user_with_roles(self):
        self._setup_assignments()
        self.r.add_rls_user("CORP\\alice", ["Region_West"])
        put_call = [c for c in self.r._client._request.call_args_list
                    if c[0][0] == "PUT"][0]
        assignments = put_call[1]["json"]
        self.assertEqual(len(assignments), 1)
        self.assertEqual(assignments[0]["GroupUserName"], "CORP\\alice")
        self.assertIn("Region_West", assignments[0]["Roles"])

    def test_merges_roles_for_existing_user(self):
        self._setup_assignments([
            {"GroupUserName": "CORP\\alice", "Roles": ["Region_West"]}
        ])
        self.r.add_rls_user("CORP\\alice", ["Region_East"])
        put_call = [c for c in self.r._client._request.call_args_list
                    if c[0][0] == "PUT"][0]
        alice = next(a for a in put_call[1]["json"]
                     if a["GroupUserName"] == "CORP\\alice")
        self.assertIn("Region_West", alice["Roles"])
        self.assertIn("Region_East", alice["Roles"])

    def test_no_duplicate_rls_roles(self):
        self._setup_assignments([
            {"GroupUserName": "CORP\\alice", "Roles": ["Region_West"]}
        ])
        self.r.add_rls_user("CORP\\alice", ["Region_West"])
        put_call = [c for c in self.r._client._request.call_args_list
                    if c[0][0] == "PUT"][0]
        alice = next(a for a in put_call[1]["json"]
                     if a["GroupUserName"] == "CORP\\alice")
        self.assertEqual(alice["Roles"].count("Region_West"), 1)

    def test_case_insensitive_username(self):
        self._setup_assignments([
            {"GroupUserName": "CORP\\Alice", "Roles": ["Region_West"]}
        ])
        self.r.add_rls_user("corp\\alice", ["Region_East"])
        put_call = [c for c in self.r._client._request.call_args_list
                    if c[0][0] == "PUT"][0]
        # Only one entry — existing one updated
        self.assertEqual(len(put_call[1]["json"]), 1)

    def test_preserves_other_users(self):
        self._setup_assignments([
            {"GroupUserName": "CORP\\alice", "Roles": ["Region_West"]}
        ])
        self.r.add_rls_user("CORP\\bob", ["Region_East"])
        put_call = [c for c in self.r._client._request.call_args_list
                    if c[0][0] == "PUT"][0]
        self.assertEqual(len(put_call[1]["json"]), 2)

    def test_calls_correct_put_endpoint(self):
        self._setup_assignments()
        self.r.add_rls_user("CORP\\alice", ["Region_West"])
        put_call = [c for c in self.r._client._request.call_args_list
                    if c[0][0] == "PUT"][0]
        self.assertEqual(put_call[0][1], "PowerBIReports(r-1)/DataModelRoleAssignments")


class TestRemoveRlsUser(unittest.TestCase):

    def setUp(self):
        self.r = _report()

    def _setup_assignments(self, assignments=None):
        self.r._client._request.return_value = {"value": assignments or []}

    def test_removes_existing_user(self):
        self._setup_assignments([
            {"GroupUserName": "CORP\\alice", "Roles": ["Region_West"]},
            {"GroupUserName": "CORP\\bob",   "Roles": ["Region_East"]},
        ])
        self.r.remove_rls_user("CORP\\alice")
        put_call = [c for c in self.r._client._request.call_args_list
                    if c[0][0] == "PUT"][0]
        usernames = [a["GroupUserName"] for a in put_call[1]["json"]]
        self.assertNotIn("CORP\\alice", usernames)
        self.assertIn("CORP\\bob", usernames)

    def test_noop_for_absent_user(self):
        self._setup_assignments([
            {"GroupUserName": "CORP\\alice", "Roles": ["Region_West"]}
        ])
        self.r.remove_rls_user("CORP\\nobody")
        put_call = [c for c in self.r._client._request.call_args_list
                    if c[0][0] == "PUT"][0]
        self.assertEqual(len(put_call[1]["json"]), 1)

    def test_case_insensitive_removal(self):
        self._setup_assignments([
            {"GroupUserName": "CORP\\Alice", "Roles": ["Region_West"]}
        ])
        self.r.remove_rls_user("corp\\alice")
        put_call = [c for c in self.r._client._request.call_args_list
                    if c[0][0] == "PUT"][0]
        self.assertEqual(put_call[1]["json"], [])

    def test_calls_correct_put_endpoint(self):
        self._setup_assignments([
            {"GroupUserName": "CORP\\alice", "Roles": ["Region_West"]}
        ])
        self.r.remove_rls_user("CORP\\alice")
        put_call = [c for c in self.r._client._request.call_args_list
                    if c[0][0] == "PUT"][0]
        self.assertEqual(put_call[0][1], "PowerBIReports(r-1)/DataModelRoleAssignments")


if __name__ == "__main__":
    unittest.main(verbosity=2)
