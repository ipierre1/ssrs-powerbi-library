"""Tests for Schedule."""

import unittest
from datetime import datetime

from ssrs_library._schedule import Schedule, _ALL_DAYS, _ALL_MONTHS


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _rec(schedule: Schedule) -> dict:
    """Shortcut to the Recurrence dict inside a to_api() result."""
    return schedule.to_api()["Definition"]["Recurrence"]


def _defn(schedule: Schedule) -> dict:
    return schedule.to_api()["Definition"]


# ---------------------------------------------------------------------------
# Schedule.daily
# ---------------------------------------------------------------------------
class TestDaily(unittest.TestCase):

    def test_default_recurrence_type(self):
        self.assertIn("DailyRecurrence", _rec(Schedule.daily()))

    def test_default_interval_is_1(self):
        self.assertEqual(_rec(Schedule.daily())["DailyRecurrence"]["DaysInterval"], "1")

    def test_default_hour_is_2(self):
        self.assertIn("T02:00:00", _defn(Schedule.daily())["StartDateTime"])

    def test_default_minute_is_0(self):
        self.assertIn(":00:00", _defn(Schedule.daily())["StartDateTime"])

    def test_custom_hour(self):
        self.assertIn("T06:00:00", _defn(Schedule.daily(hour=6))["StartDateTime"])

    def test_custom_minute(self):
        self.assertIn(
            "T02:30:00", _defn(Schedule.daily(hour=2, minute=30))["StartDateTime"]
        )

    def test_custom_interval(self):
        self.assertEqual(
            _rec(Schedule.daily(interval=3))["DailyRecurrence"]["DaysInterval"], "3"
        )

    def test_hour_0_allowed(self):
        s = Schedule.daily(hour=0)
        self.assertIn("T00:00:00", _defn(s)["StartDateTime"])

    def test_hour_23_allowed(self):
        Schedule.daily(hour=23)  # should not raise

    def test_invalid_hour_too_high(self):
        with self.assertRaises(ValueError):
            Schedule.daily(hour=24)

    def test_invalid_hour_negative(self):
        with self.assertRaises(ValueError):
            Schedule.daily(hour=-1)

    def test_invalid_minute_too_high(self):
        with self.assertRaises(ValueError):
            Schedule.daily(minute=60)

    def test_invalid_minute_negative(self):
        with self.assertRaises(ValueError):
            Schedule.daily(minute=-1)

    def test_invalid_interval_zero(self):
        with self.assertRaises(ValueError):
            Schedule.daily(interval=0)

    def test_invalid_interval_negative(self):
        with self.assertRaises(ValueError):
            Schedule.daily(interval=-1)

    def test_custom_start_date(self):
        dt = datetime(2030, 6, 15, 0, 0, 0)
        result = _defn(Schedule.daily(hour=4, start_date=dt))["StartDateTime"]
        self.assertEqual(result, "2030-06-15T04:00:00")

    def test_repr_contains_type(self):
        self.assertIn("DailyRecurrence", repr(Schedule.daily()))

    def test_repr_contains_time(self):
        self.assertIn("02:00", repr(Schedule.daily(hour=2)))


# ---------------------------------------------------------------------------
# Schedule.weekly
# ---------------------------------------------------------------------------
class TestWeekly(unittest.TestCase):

    def test_default_recurrence_type(self):
        self.assertIn("WeeklyRecurrence", _rec(Schedule.weekly(["Monday"])))

    def test_selected_day_is_true(self):
        days = _rec(Schedule.weekly(["Monday"]))["WeeklyRecurrence"]["DaysOfWeek"]
        self.assertTrue(days["Monday"])

    def test_unselected_day_is_false(self):
        days = _rec(Schedule.weekly(["Monday"]))["WeeklyRecurrence"]["DaysOfWeek"]
        self.assertFalse(days["Tuesday"])

    def test_multiple_days(self):
        days = _rec(Schedule.weekly(["Monday", "Friday"]))["WeeklyRecurrence"][
            "DaysOfWeek"
        ]
        self.assertTrue(days["Monday"])
        self.assertTrue(days["Friday"])
        self.assertFalse(days["Wednesday"])

    def test_all_seven_days_present_in_map(self):
        days = _rec(Schedule.weekly(["Sunday"]))["WeeklyRecurrence"]["DaysOfWeek"]
        self.assertEqual(set(days.keys()), set(_ALL_DAYS))

    def test_default_interval_is_1(self):
        rec = _rec(Schedule.weekly(["Monday"]))["WeeklyRecurrence"]
        self.assertEqual(rec["WeeksInterval"], "1")

    def test_custom_interval(self):
        rec = _rec(Schedule.weekly(["Monday"], interval=2))["WeeklyRecurrence"]
        self.assertEqual(rec["WeeksInterval"], "2")

    def test_case_insensitive_days(self):
        days = _rec(Schedule.weekly(["monday", "FRIDAY"]))["WeeklyRecurrence"][
            "DaysOfWeek"
        ]
        self.assertTrue(days["Monday"])
        self.assertTrue(days["Friday"])

    def test_custom_hour(self):
        self.assertIn(
            "T08:00:00", _defn(Schedule.weekly(["Monday"], hour=8))["StartDateTime"]
        )

    def test_custom_minute(self):
        self.assertIn(
            "T08:30:00",
            _defn(Schedule.weekly(["Monday"], hour=8, minute=30))["StartDateTime"],
        )

    def test_empty_days_raises(self):
        with self.assertRaises(ValueError):
            Schedule.weekly([])

    def test_invalid_day_raises(self):
        with self.assertRaises(ValueError):
            Schedule.weekly(["Funday"])

    def test_invalid_hour_raises(self):
        with self.assertRaises(ValueError):
            Schedule.weekly(["Monday"], hour=25)

    def test_invalid_minute_raises(self):
        with self.assertRaises(ValueError):
            Schedule.weekly(["Monday"], minute=60)

    def test_repr_contains_type(self):
        self.assertIn("WeeklyRecurrence", repr(Schedule.weekly(["Monday"])))


# ---------------------------------------------------------------------------
# Schedule.monthly
# ---------------------------------------------------------------------------
class TestMonthly(unittest.TestCase):

    def test_default_recurrence_type(self):
        self.assertIn("MonthlyRecurrence", _rec(Schedule.monthly()))

    def test_default_day_is_1(self):
        self.assertEqual(_rec(Schedule.monthly())["MonthlyRecurrence"]["Days"], "1")

    def test_custom_day(self):
        self.assertEqual(
            _rec(Schedule.monthly(day=15))["MonthlyRecurrence"]["Days"], "15"
        )

    def test_all_months_true_by_default(self):
        months = _rec(Schedule.monthly())["MonthlyRecurrence"]["MonthsOfYear"]
        self.assertTrue(all(months.values()))

    def test_all_twelve_months_in_map(self):
        months = _rec(Schedule.monthly())["MonthlyRecurrence"]["MonthsOfYear"]
        self.assertEqual(set(months.keys()), set(_ALL_MONTHS))

    def test_specific_months(self):
        months = _rec(Schedule.monthly(months=["January", "July"]))[
            "MonthlyRecurrence"
        ]["MonthsOfYear"]
        self.assertTrue(months["January"])
        self.assertTrue(months["July"])
        self.assertFalse(months["February"])
        self.assertFalse(months["December"])

    def test_case_insensitive_months(self):
        months = _rec(Schedule.monthly(months=["january", "JULY"]))[
            "MonthlyRecurrence"
        ]["MonthsOfYear"]
        self.assertTrue(months["January"])
        self.assertTrue(months["July"])

    def test_custom_hour_minute(self):
        self.assertIn(
            "T03:15:00", _defn(Schedule.monthly(hour=3, minute=15))["StartDateTime"]
        )

    def test_day_1_allowed(self):
        Schedule.monthly(day=1)  # should not raise

    def test_day_28_allowed(self):
        Schedule.monthly(day=28)  # should not raise

    def test_invalid_day_0(self):
        with self.assertRaises(ValueError):
            Schedule.monthly(day=0)

    def test_invalid_day_29(self):
        with self.assertRaises(ValueError):
            Schedule.monthly(day=29)

    def test_invalid_month(self):
        with self.assertRaises(ValueError):
            Schedule.monthly(months=["Octember"])

    def test_invalid_hour(self):
        with self.assertRaises(ValueError):
            Schedule.monthly(hour=-1)

    def test_invalid_minute(self):
        with self.assertRaises(ValueError):
            Schedule.monthly(minute=60)

    def test_repr_contains_type(self):
        self.assertIn("MonthlyRecurrence", repr(Schedule.monthly()))


# ---------------------------------------------------------------------------
# to_api structure (PBIRS-exact shape)
# ---------------------------------------------------------------------------
class TestToApiStructure(unittest.TestCase):
    """Verify the exact JSON shape expected by the PBIRS REST API."""

    def test_top_level_key_is_definition(self):
        api = Schedule.daily().to_api()
        self.assertEqual(list(api.keys()), ["Definition"])

    def test_definition_has_required_keys(self):
        defn = Schedule.daily().to_api()["Definition"]
        for key in ("StartDateTime", "EndDateSpecified", "EndDate", "Recurrence"):
            self.assertIn(key, defn)

    def test_end_date_specified_is_false(self):
        self.assertFalse(Schedule.daily().to_api()["Definition"]["EndDateSpecified"])

    def test_end_date_sentinel_value(self):
        self.assertEqual(
            Schedule.daily().to_api()["Definition"]["EndDate"],
            "1901-01-01T00:00:00",
        )

    def test_start_datetime_is_parseable_iso8601(self):
        dt_str = Schedule.daily(hour=6, minute=30).to_api()["Definition"][
            "StartDateTime"
        ]
        parsed = datetime.strptime(dt_str, "%Y-%m-%dT%H:%M:%S")
        self.assertEqual(parsed.hour, 6)
        self.assertEqual(parsed.minute, 30)
        self.assertEqual(parsed.second, 0)

    def test_daily_interval_is_string(self):
        """The API expects DaysInterval as a string, not an integer."""
        rec = Schedule.daily(interval=2).to_api()["Definition"]["Recurrence"]
        self.assertIsInstance(rec["DailyRecurrence"]["DaysInterval"], str)

    def test_weekly_interval_is_string(self):
        rec = Schedule.weekly(["Monday"], interval=2).to_api()["Definition"][
            "Recurrence"
        ]
        self.assertIsInstance(rec["WeeklyRecurrence"]["WeeksInterval"], str)

    def test_monthly_day_is_string(self):
        rec = Schedule.monthly(day=5).to_api()["Definition"]["Recurrence"]
        self.assertIsInstance(rec["MonthlyRecurrence"]["Days"], str)

    def test_days_of_week_values_are_booleans(self):
        days = Schedule.weekly(["Monday"]).to_api()["Definition"]["Recurrence"][
            "WeeklyRecurrence"
        ]["DaysOfWeek"]
        for v in days.values():
            self.assertIsInstance(v, bool)

    def test_months_of_year_values_are_booleans(self):
        months = Schedule.monthly().to_api()["Definition"]["Recurrence"][
            "MonthlyRecurrence"
        ]["MonthsOfYear"]
        for v in months.values():
            self.assertIsInstance(v, bool)


if __name__ == "__main__":
    unittest.main(verbosity=2)
