from typing import Any, Dict, List, Optional, Union, TYPE_CHECKING

if TYPE_CHECKING:
    from .client import PBIRSClient

from ._datasource import DataSource
from ._cache_refresh_plan import CacheRefreshPlan
from ._schedule import Schedule


class PaginatedReport:
    """
    Handle on a paginated (SSRS) report (.rdl) stored in PBIRS.

    Obtained via :meth:`PBIRSClient.get_paginated_report`,
    :meth:`PBIRSClient.list_paginated_reports`, or
    :meth:`PBIRSClient.upload_paginated_report`::

        report = client.get_paginated_report("/Finance/Monthly")
        ds = report.get_datasources()
    """

    def __init__(self, client: "PBIRSClient", data: Dict[str, Any]):
        self._client = client
        self._data = data

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def id(self) -> str:
        return self._data["Id"]

    @property
    def name(self) -> str:
        return self._data["Name"]

    @property
    def path(self) -> str:
        return self._data["Path"]

    @property
    def description(self) -> str:
        return self._data.get("Description", "")

    @property
    def has_data_sources(self) -> bool:
        return self._data.get("HasDataSources", False)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def delete(self) -> None:
        """Permanently delete this report from the catalog."""
        self._client._request("DELETE", f"Reports({self.id})")

    # ------------------------------------------------------------------
    # Data sources
    # ------------------------------------------------------------------

    def get_datasources(self) -> List[DataSource]:
        """Return the data sources bound to this report."""
        data = self._client._request("GET", f"Reports({self.id})/DataSources")
        return [DataSource.from_api(ds) for ds in data.get("value", [])]

    def set_datasources(self, datasources: List[DataSource]) -> None:
        """
        Replace all data sources on this report.

        :param datasources: List of :class:`DataSource` objects.
        """
        payload = [ds.to_api() for ds in datasources]
        self._client._request(
            "PUT", f"Reports({self.id})/DataSources", json=payload
        )

    # ------------------------------------------------------------------
    # Report parameters
    # ------------------------------------------------------------------

    def get_parameters(self) -> List[Dict[str, Any]]:
        """Return the report parameter definitions."""
        data = self._client._request(
            "GET", f"Reports({self.id})/ParameterDefinitions"
        )
        return data.get("value", [])

    def set_parameters(self, parameters: List[Dict[str, Any]]) -> None:
        """
        Update report parameter definitions.

        :param parameters: List of parameter definition dicts
            (same structure returned by :meth:`get_parameters`).
        """
        self._client._request(
            "PATCH",
            f"Reports({self.id})/ParameterDefinitions",
            json=parameters,
        )

    # ------------------------------------------------------------------
    # Cache refresh plans
    # ------------------------------------------------------------------

    def get_cache_refresh_plans(self) -> List[CacheRefreshPlan]:
        """Return cache-refresh plans attached to this report."""
        data = self._client._request(
            "GET", f"Reports({self.id})/CacheRefreshPlans"
        )
        return [
            CacheRefreshPlan(self._client, p) for p in data.get("value", [])
        ]

    def create_cache_refresh_plan(
        self,
        description: str = "",
        schedule: Optional[Union[Schedule, Dict[str, Any]]] = None,
        event_type: str = "TimedSubscription",
    ) -> CacheRefreshPlan:
        """
        Create a new cache-refresh plan for this paginated report.

        :param description: Human-readable description.
        :param schedule: A :class:`~ssrs_library.Schedule` instance
            **or** a raw ``Schedule.Definition`` dict.
            When omitted the server uses its default.

            Examples::

                report.create_cache_refresh_plan(
                    description="Daily at 3 AM",
                    schedule=Schedule.daily(hour=3),
                )

                report.create_cache_refresh_plan(
                    description="Every Monday",
                    schedule=Schedule.weekly(["Monday"], hour=6),
                )

        :param event_type: Usually ``"TimedSubscription"`` for paginated
            reports.
        :returns: The new :class:`CacheRefreshPlan`.
        """
        payload: Dict[str, Any] = {
            "CatalogItemPath": self.path,
            "EventType": event_type,
            "Description": description,
        }
        if schedule is not None:
            payload["Schedule"] = (
                schedule.to_api()
                if isinstance(schedule, Schedule)
                else schedule
            )
        data = self._client._request("POST", "CacheRefreshPlans", json=payload)
        return CacheRefreshPlan(self._client, data)

    # ------------------------------------------------------------------
    # Security policies (catalog-level access control)
    # ------------------------------------------------------------------

    def get_policies(self) -> Dict[str, Any]:
        """
        Return the catalog security policies on this report.

        The returned dict has two keys:

        * ``"InheritParentSecurity"`` (*bool*)
        * ``"Policies"`` (*list*) — each entry is
          ``{"GroupUserName": "CORP\\\\name", "Roles": [{"RoleName": "Browser"}]}``.

        Built-in role names: ``"Browser"``, ``"Content Manager"``,
        ``"Publisher"``, ``"Report Builder"``.
        """
        data = self._client._request(
            "GET", f"Reports({self.id})/Policies"
        )
        return data or {"InheritParentSecurity": False, "Policies": []}

    def set_policies(self, policy_data: Dict[str, Any]) -> None:
        """
        Replace the catalog security policies on this report (full overwrite).

        :param policy_data: Dict as returned by :meth:`get_policies`.

        Example::

            policies = report.get_policies()
            policies["InheritParentSecurity"] = False
            policies["Policies"] = [
                {"GroupUserName": "CORP\\\\viewers", "Roles": [{"RoleName": "Browser"}]},
            ]
            report.set_policies(policies)
        """
        self._client._request(
            "PUT", f"Reports({self.id})/Policies", json=policy_data
        )

    def add_user(self, username: str, roles: List[str]) -> None:
        """
        Grant *username* the specified catalog *roles* on this report.

        Uses a read-modify-write pattern.  Existing roles for *username*
        are merged (no duplicates).

        :param username: e.g. ``"CORP\\\\alice"`` or ``"CORP\\\\Sales Team"``.
        :param roles: e.g. ``["Browser"]`` or ``["Content Manager"]``.
        """
        data = self.get_policies()
        role_objs = [{"RoleName": r} for r in roles]

        for entry in data.get("Policies", []):
            if entry.get("GroupUserName", "").lower() == username.lower():
                existing = {r["RoleName"] for r in entry.get("Roles", [])}
                entry["Roles"] = [{"RoleName": r} for r in existing | set(roles)]
                self.set_policies(data)
                return

        data.setdefault("Policies", []).append(
            {"GroupUserName": username, "Roles": role_objs}
        )
        self.set_policies(data)

    def remove_user(self, username: str) -> None:
        """
        Remove *username* from all catalog security policies on this report.

        Uses a read-modify-write pattern.  No-op if *username* is not present.

        :param username: e.g. ``"CORP\\\\alice"``.
        """
        data = self.get_policies()
        data["Policies"] = [
            p for p in data.get("Policies", [])
            if p.get("GroupUserName", "").lower() != username.lower()
        ]
        self.set_policies(data)

    def __repr__(self) -> str:
        return f"<PaginatedReport name={self.name!r} path={self.path!r}>"
