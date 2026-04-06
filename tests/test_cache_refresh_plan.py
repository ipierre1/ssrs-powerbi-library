"""Tests for CacheRefreshPlan."""

import unittest
from unittest.mock import Mock

from ssrs_library._cache_refresh_plan import CacheRefreshPlan
from ssrs_library._schedule import Schedule

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
PLAN_DATA = {
    "Id": "p-1",
    "Description": "Nightly refresh",
    "EventType": "DataModelRefresh",
    "CatalogItemPath": "/Sales/Revenue",
    "Schedule": {
        "Definition": {
            "StartDateTime": "2025-01-01T02:00:00",
            "EndDateSpecified": False,
            "EndDate": "1901-01-01T00:00:00",
            "Recurrence": {"DailyRecurrence": {"DaysInterval": "1"}},
        }
    },
}


def _plan(data=None):
    return CacheRefreshPlan(Mock(), data or PLAN_DATA)


# ---------------------------------------------------------------------------
# Properties
# ---------------------------------------------------------------------------
class TestProperties(unittest.TestCase):

    def setUp(self):
        self.p = _plan()

    def test_id(self):
        self.assertEqual(self.p.id, "p-1")

    def test_description(self):
        self.assertEqual(self.p.description, "Nightly refresh")

    def test_event_type(self):
        self.assertEqual(self.p.event_type, "DataModelRefresh")

    def test_catalog_item_path(self):
        self.assertEqual(self.p.catalog_item_path, "/Sales/Revenue")

    def test_schedule_not_none(self):
        self.assertIsNotNone(self.p.schedule)

    def test_schedule_has_definition(self):
        self.assertIn("Definition", self.p.schedule)

    def test_description_missing_defaults_empty(self):
        p = _plan({"Id": "x", "EventType": "DataModelRefresh"})
        self.assertEqual(p.description, "")

    def test_catalog_item_path_missing_is_none(self):
        p = _plan({"Id": "x", "EventType": "DataModelRefresh"})
        self.assertIsNone(p.catalog_item_path)

    def test_schedule_missing_is_none(self):
        p = _plan({"Id": "x", "EventType": "DataModelRefresh"})
        self.assertIsNone(p.schedule)

    def test_repr_contains_id(self):
        self.assertIn("p-1", repr(self.p))

    def test_repr_contains_description(self):
        self.assertIn("Nightly refresh", repr(self.p))

    def test_repr_contains_event_type(self):
        self.assertIn("DataModelRefresh", repr(self.p))


# ---------------------------------------------------------------------------
# execute
# ---------------------------------------------------------------------------
class TestExecute(unittest.TestCase):

    def test_posts_to_execute_endpoint(self):
        p = _plan()
        p.execute()
        p._client._request.assert_called_once_with(
            "POST", "CacheRefreshPlans(p-1)/Execute"
        )


# ---------------------------------------------------------------------------
# update
# ---------------------------------------------------------------------------
class TestUpdate(unittest.TestCase):

    def setUp(self):
        self.p = _plan()
        self.p._client._request.return_value = None  # PUT returns 204

    def test_update_description_only(self):
        self.p.update(description="New label")
        payload = self.p._client._request.call_args[1]["json"]
        self.assertEqual(payload["Description"], "New label")

    def test_update_with_schedule_object(self):
        self.p.update(schedule=Schedule.weekly(["Monday"], hour=6))
        payload = self.p._client._request.call_args[1]["json"]
        self.assertIn("Schedule", payload)
        rec = payload["Schedule"]["Definition"]["Recurrence"]
        self.assertIn("WeeklyRecurrence", rec)
        self.assertTrue(rec["WeeklyRecurrence"]["DaysOfWeek"]["Monday"])

    def test_update_with_daily_schedule_object(self):
        self.p.update(schedule=Schedule.daily(hour=4))
        payload = self.p._client._request.call_args[1]["json"]
        rec = payload["Schedule"]["Definition"]["Recurrence"]
        self.assertIn("DailyRecurrence", rec)
        self.assertIn("T04:00:00", payload["Schedule"]["Definition"]["StartDateTime"])

    def test_update_with_monthly_schedule_object(self):
        self.p.update(schedule=Schedule.monthly(day=1, hour=3))
        payload = self.p._client._request.call_args[1]["json"]
        rec = payload["Schedule"]["Definition"]["Recurrence"]
        self.assertIn("MonthlyRecurrence", rec)

    def test_update_with_raw_dict(self):
        raw = {"Definition": {"StartDateTime": "2025-06-01T04:00:00"}}
        self.p.update(schedule=raw)
        payload = self.p._client._request.call_args[1]["json"]
        self.assertEqual(payload["Schedule"], raw)

    def test_update_both_description_and_schedule(self):
        self.p.update(description="Updated", schedule=Schedule.daily(hour=4))
        payload = self.p._client._request.call_args[1]["json"]
        self.assertEqual(payload["Description"], "Updated")
        self.assertIn("Schedule", payload)

    def test_update_no_args_still_sends_put(self):
        self.p.update()
        self.p._client._request.assert_called_once()
        method, endpoint = self.p._client._request.call_args[0]
        self.assertEqual(method, "PUT")
        self.assertEqual(endpoint, "CacheRefreshPlans(p-1)")

    def test_update_returns_self(self):
        result = self.p.update(description="X")
        self.assertIs(result, self.p)

    def test_update_refreshes_data_from_server_response(self):
        updated = {**PLAN_DATA, "Description": "Server-side label"}
        self.p._client._request.return_value = updated
        self.p.update(description="Server-side label")
        self.assertEqual(self.p.description, "Server-side label")

    def test_update_falls_back_to_local_payload_when_server_returns_none(self):
        """Server returns 204/None → local payload used as fallback."""
        self.p._client._request.return_value = None
        self.p.update(description="Local fallback")
        self.assertEqual(self.p.description, "Local fallback")

    def test_update_calls_put_endpoint(self):
        self.p.update()
        method, endpoint = self.p._client._request.call_args[0]
        self.assertEqual(method, "PUT")
        self.assertEqual(endpoint, "CacheRefreshPlans(p-1)")

    def test_update_includes_existing_data_in_payload(self):
        """Existing plan data is included so no fields are lost."""
        self.p.update(description="X")
        payload = self.p._client._request.call_args[1]["json"]
        self.assertIn("EventType", payload)
        self.assertEqual(payload["EventType"], "DataModelRefresh")


# ---------------------------------------------------------------------------
# delete
# ---------------------------------------------------------------------------
class TestDelete(unittest.TestCase):

    def test_calls_delete_endpoint(self):
        p = _plan()
        p.delete()
        p._client._request.assert_called_once_with(
            "DELETE", "CacheRefreshPlans(p-1)"
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
