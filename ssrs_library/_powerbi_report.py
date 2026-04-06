from typing import Any, Dict, List, Optional, Union, TYPE_CHECKING

if TYPE_CHECKING:
    from .client import PBIRSClient

from ._datasource import DataSource
from ._cache_refresh_plan import CacheRefreshPlan
from ._schedule import Schedule


class PowerBIReport:
    """
    Handle on a Power BI report (.pbix) stored in PBIRS.

    Obtained via :meth:`PBIRSClient.get_powerbi_report`,
    :meth:`PBIRSClient.list_powerbi_reports`, or
    :meth:`PBIRSClient.upload_powerbi_report`::

        report = client.get_powerbi_report("/Sales/Revenue")
        report.set_data_model_parameters([
            {"Name": "StartYear", "Value": "2024"},
        ])
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
        self._client._request("DELETE", f"PowerBIReports({self.id})")

    # ------------------------------------------------------------------
    # Data sources
    # ------------------------------------------------------------------

    def get_datasources(self) -> List[DataSource]:
        """Return the data sources bound to this report."""
        data = self._client._request(
            "GET", f"PowerBIReports({self.id})/DataSources"
        )
        return [DataSource.from_api(ds) for ds in data.get("value", [])]

    def set_datasources(self, datasources: List[DataSource]) -> None:
        """
        Replace all data sources on this report.

        :param datasources: List of :class:`DataSource` objects.
        """
        payload = [ds.to_api() for ds in datasources]
        self._client._request(
            "PUT", f"PowerBIReports({self.id})/DataSources", json=payload
        )

    # ------------------------------------------------------------------
    # Data model parameters
    # ------------------------------------------------------------------

    def get_data_model_parameters(self) -> List[Dict[str, Any]]:
        """
        Return the current data-model parameter values.

        Each item is a dict with at least ``"Name"`` and ``"Value"`` keys.
        """
        data = self._client._request(
            "GET", f"PowerBIReports({self.id})/DataModelParameters"
        )
        return data.get("value", [])

    def set_data_model_parameters(
        self, parameters: List[Dict[str, Any]]
    ) -> None:
        """
        Set data-model parameters.

        :param parameters: List of ``{"Name": ..., "Value": ...}`` dicts.

        Example::

            report.set_data_model_parameters([
                {"Name": "Environment", "Value": "Production"},
                {"Name": "MaxRows",     "Value": "10000"},
            ])
        """
        self._client._request(
            "PUT",
            f"PowerBIReports({self.id})/DataModelParameters",
            json=parameters,
        )

    # ------------------------------------------------------------------
    # Cache refresh plans
    # ------------------------------------------------------------------

    def get_cache_refresh_plans(self) -> List[CacheRefreshPlan]:
        """Return cache-refresh plans attached to this report."""
        data = self._client._request(
            "GET", f"PowerBIReports({self.id})/CacheRefreshPlans"
        )
        return [
            CacheRefreshPlan(self._client, p) for p in data.get("value", [])
        ]

    def create_cache_refresh_plan(
        self,
        description: str = "",
        schedule: Optional[Union[Schedule, Dict[str, Any]]] = None,
    ) -> CacheRefreshPlan:
        """
        Create a new cache-refresh plan for this Power BI report.

        :param description: Human-readable description.
        :param schedule: A :class:`~ssrs_library.Schedule` instance
            **or** a raw ``Schedule.Definition`` dict.
            When omitted the server uses its default (usually daily).

            Examples::

                report.create_cache_refresh_plan(
                    description="Nightly refresh",
                    schedule=Schedule.daily(hour=2),
                )

                report.create_cache_refresh_plan(
                    description="Monday & Friday at 08:30",
                    schedule=Schedule.weekly(["Monday", "Friday"], hour=8, minute=30),
                )

                report.create_cache_refresh_plan(
                    description="1st of every month",
                    schedule=Schedule.monthly(day=1, hour=3),
                )

        :returns: The new :class:`CacheRefreshPlan`.
        """
        payload: Dict[str, Any] = {
            "CatalogItemPath": self.path,
            "EventType": "DataModelRefresh",
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
            "GET", f"PowerBIReports({self.id})/Policies"
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
            "PUT", f"PowerBIReports({self.id})/Policies", json=policy_data
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

    # ------------------------------------------------------------------
    # Row-level security (data model roles)
    # ------------------------------------------------------------------

    def get_data_model_roles(self) -> List[Dict[str, Any]]:
        """Return the RLS roles defined in the report's data model."""
        data = self._client._request(
            "GET", f"PowerBIReports({self.id})/DataModelRoles"
        )
        return data.get("value", [])

    def get_data_model_role_assignments(self) -> List[Dict[str, Any]]:
        """Return current user-to-role assignments for this report."""
        data = self._client._request(
            "GET", f"PowerBIReports({self.id})/DataModelRoleAssignments"
        )
        return data.get("value", [])

    def set_data_model_role_assignments(
        self, assignments: List[Dict[str, Any]]
    ) -> None:
        """
        Replace all RLS role assignments.

        :param assignments: List of ``{"GroupUserName": ..., "Roles": [...]}`` dicts.

        Example::

            report.set_data_model_role_assignments([
                {"GroupUserName": "DOMAIN\\alice", "Roles": ["Region_West"]},
                {"GroupUserName": "DOMAIN\\bob",   "Roles": ["Region_East"]},
            ])
        """
        self._client._request(
            "PUT",
            f"PowerBIReports({self.id})/DataModelRoleAssignments",
            json=assignments,
        )

    def add_rls_user(self, username: str, role_names: List[str]) -> None:
        """
        Assign *username* to the given RLS *role_names*.

        Uses a read-modify-write pattern.  If *username* already has
        assignments, the new roles are merged (no duplicates).

        :param username: Domain-qualified name, e.g. ``"CORP\\\\alice"``.
        :param role_names: Data-model role names as strings,
            e.g. ``["Region_West"]``.

        Example::

            report.add_rls_user("CORP\\\\alice", ["Region_West"])
            report.add_rls_user("CORP\\\\managers", ["Region_West", "Region_East"])
        """
        current = self.get_data_model_role_assignments()
        for entry in current:
            if entry.get("GroupUserName", "").lower() == username.lower():
                merged = list(set(entry.get("Roles", [])) | set(role_names))
                entry["Roles"] = merged
                self.set_data_model_role_assignments(current)
                return
        current.append({"GroupUserName": username, "Roles": list(role_names)})
        self.set_data_model_role_assignments(current)

    def remove_rls_user(self, username: str) -> None:
        """
        Remove *username* from all RLS role assignments.

        Uses a read-modify-write pattern.  No-op if *username* is not present.

        :param username: Domain-qualified name, e.g. ``"CORP\\\\alice"``.
        """
        current = self.get_data_model_role_assignments()
        updated = [
            a for a in current
            if a.get("GroupUserName", "").lower() != username.lower()
        ]
        self.set_data_model_role_assignments(updated)

    def __repr__(self) -> str:
        return f"<PowerBIReport name={self.name!r} path={self.path!r}>"
