"""
Convenience builders for PBIRS cache-refresh plan schedule definitions.

The :class:`Schedule` class produces the ``"Schedule"`` payload fragment
expected by the ``POST /CacheRefreshPlans`` and ``PUT /CacheRefreshPlans``
endpoints, matching the structure used by the official PowerShell
``New-RsRestCacheRefreshPlan`` cmdlet.

Quick reference::

    from ssrs_library import Schedule

    Schedule.daily(hour=2)
    Schedule.daily(hour=6, minute=30, interval=2)      # every 2 days at 06:30
    Schedule.weekly(days=["Monday", "Friday"], hour=8)
    Schedule.weekly(days=["Wednesday"], hour=0, interval=2)  # bi-weekly
    Schedule.monthly(day=1, hour=3)                    # 1st of every month at 03:00
    Schedule.monthly(day=15, hour=12, months=["January", "July"])
"""

from datetime import datetime
from typing import Any, Dict, List, Optional

# Ordered so that the API receives them in a predictable sequence.
_ALL_DAYS = [
    "Sunday", "Monday", "Tuesday", "Wednesday",
    "Thursday", "Friday", "Saturday",
]
_ALL_MONTHS = [
    "January", "February", "March", "April", "May", "June",
    "July", "August", "September", "October", "November", "December",
]

# Sentinel used as the default start-date: means "use today at the given time".
_TODAY = object()


class Schedule:
    """
    Immutable schedule definition for a PBIRS cache-refresh plan.

    Do **not** instantiate directly — use the class-method constructors:

    * :meth:`daily`
    * :meth:`weekly`
    * :meth:`monthly`

    A ``Schedule`` instance can be passed anywhere the library accepts a
    *schedule* argument, e.g.::

        plan = report.create_cache_refresh_plan(
            description="Nightly ETL",
            schedule=Schedule.daily(hour=2),
        )

        plan.update(schedule=Schedule.weekly(days=["Monday"], hour=6))
    """

    def __init__(self, recurrence: Dict[str, Any], hour: int, minute: int,
                 start_date: Optional[datetime]):
        self._recurrence = recurrence
        self._hour = hour
        self._minute = minute
        # Resolve sentinel to today.
        if start_date is _TODAY or start_date is None:
            start_date = datetime.now()
        self._start = start_date.replace(
            hour=hour, minute=minute, second=0, microsecond=0
        )

    # ------------------------------------------------------------------
    # Constructors
    # ------------------------------------------------------------------

    @classmethod
    def daily(
        cls,
        hour: int = 2,
        minute: int = 0,
        interval: int = 1,
        start_date: Optional[datetime] = None,
    ) -> "Schedule":
        """
        Refresh every *interval* day(s) at *hour*:*minute*.

        :param hour: Hour of day in 24-h format (0–23). Default ``2``.
        :param minute: Minute (0–59). Default ``0``.
        :param interval: Repeat every N days. Default ``1`` (every day).
        :param start_date: First run date/time.  Defaults to today at
            *hour*:*minute*.

        Examples::

            Schedule.daily()                      # every day at 02:00
            Schedule.daily(hour=6, minute=30)     # every day at 06:30
            Schedule.daily(hour=0, interval=2)    # every 2 days at midnight
        """
        if not 0 <= hour <= 23:
            raise ValueError(f"hour must be 0–23, got {hour}")
        if not 0 <= minute <= 59:
            raise ValueError(f"minute must be 0–59, got {minute}")
        if interval < 1:
            raise ValueError(f"interval must be >= 1, got {interval}")

        recurrence = {"DailyRecurrence": {"DaysInterval": str(interval)}}
        return cls(recurrence, hour=hour, minute=minute,
                   start_date=start_date or _TODAY)  # type: ignore[arg-type]

    @classmethod
    def weekly(
        cls,
        days: List[str],
        hour: int = 2,
        minute: int = 0,
        interval: int = 1,
        start_date: Optional[datetime] = None,
    ) -> "Schedule":
        """
        Refresh every *interval* week(s) on the given *days* at *hour*:*minute*.

        :param days: One or more day names (case-insensitive), e.g.
            ``["Monday", "Friday"]``.
        :param hour: Hour of day in 24-h format (0–23). Default ``2``.
        :param minute: Minute (0–59). Default ``0``.
        :param interval: Repeat every N weeks. Default ``1``.
        :param start_date: First run date/time.  Defaults to today.

        Examples::

            Schedule.weekly(["Monday"])
            Schedule.weekly(["Monday", "Thursday"], hour=8, minute=30)
            Schedule.weekly(["Friday"], hour=22, interval=2)  # bi-weekly
        """
        if not days:
            raise ValueError("At least one day must be specified.")
        if not 0 <= hour <= 23:
            raise ValueError(f"hour must be 0–23, got {hour}")
        if not 0 <= minute <= 59:
            raise ValueError(f"minute must be 0–59, got {minute}")

        # Normalise to title-case and validate.
        normalised = [d.strip().title() for d in days]
        unknown = [d for d in normalised if d not in _ALL_DAYS]
        if unknown:
            raise ValueError(
                f"Unknown day(s): {unknown}. "
                f"Valid values: {_ALL_DAYS}"
            )

        days_map = {d: (d in normalised) for d in _ALL_DAYS}
        recurrence = {
            "WeeklyRecurrence": {
                "WeeksInterval": str(interval),
                "DaysOfWeek": days_map,
            }
        }
        return cls(recurrence, hour=hour, minute=minute,
                   start_date=start_date or _TODAY)  # type: ignore[arg-type]

    @classmethod
    def monthly(
        cls,
        day: int = 1,
        hour: int = 2,
        minute: int = 0,
        months: Optional[List[str]] = None,
        start_date: Optional[datetime] = None,
    ) -> "Schedule":
        """
        Refresh on the *day*-th of each month (or the listed *months*) at
        *hour*:*minute*.

        :param day: Day of the month (1–28). Default ``1``.
        :param hour: Hour of day in 24-h format (0–23). Default ``2``.
        :param minute: Minute (0–59). Default ``0``.
        :param months: Restrict to specific months (case-insensitive).
            Defaults to all twelve months.
        :param start_date: First run date/time.  Defaults to today.

        Examples::

            Schedule.monthly(day=1)                           # 1st of every month at 02:00
            Schedule.monthly(day=15, hour=6)                  # 15th of every month at 06:00
            Schedule.monthly(day=1, months=["January","July"])  # semi-annual
        """
        if not 1 <= day <= 28:
            raise ValueError(f"day must be 1–28, got {day}")
        if not 0 <= hour <= 23:
            raise ValueError(f"hour must be 0–23, got {hour}")
        if not 0 <= minute <= 59:
            raise ValueError(f"minute must be 0–59, got {minute}")

        if months is None:
            months = list(_ALL_MONTHS)
        else:
            normalised_months = [m.strip().title() for m in months]
            unknown = [m for m in normalised_months if m not in _ALL_MONTHS]
            if unknown:
                raise ValueError(
                    f"Unknown month(s): {unknown}. "
                    f"Valid values: {_ALL_MONTHS}"
                )
            months = normalised_months

        months_map = {m: (m in months) for m in _ALL_MONTHS}
        recurrence = {
            "MonthlyRecurrence": {
                "Days": str(day),
                "MonthsOfYear": months_map,
            }
        }
        return cls(recurrence, hour=hour, minute=minute,
                   start_date=start_date or _TODAY)  # type: ignore[arg-type]

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def to_api(self) -> Dict[str, Any]:
        """
        Return the ``"Schedule"`` dict ready for the PBIRS REST API.

        The returned structure matches the ``Schedule.Definition`` shape
        expected by ``POST /CacheRefreshPlans``::

            {
                "Definition": {
                    "StartDateTime": "2025-01-01T02:00:00",
                    "EndDateSpecified": False,
                    "EndDate": "1901-01-01T00:00:00",
                    "Recurrence": { "DailyRecurrence": {"DaysInterval": "1"} }
                }
            }
        """
        return {
            "Definition": {
                "StartDateTime": self._start.strftime("%Y-%m-%dT%H:%M:%S"),
                "EndDateSpecified": False,
                "EndDate": "1901-01-01T00:00:00",
                "Recurrence": self._recurrence,
            }
        }

    def __repr__(self) -> str:
        kind = next(iter(self._recurrence))  # e.g. "DailyRecurrence"
        return (
            f"<Schedule type={kind!r} "
            f"at={self._hour:02d}:{self._minute:02d}>"
        )
