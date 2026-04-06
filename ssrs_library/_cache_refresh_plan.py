from typing import Any, Dict, Optional, Union


class CacheRefreshPlan:
    """
    Handle on a cache-refresh plan attached to a report.

    Obtained via :meth:`PowerBIReport.get_cache_refresh_plans`,
    :meth:`PowerBIReport.create_cache_refresh_plan`,
    :meth:`PaginatedReport.get_cache_refresh_plans`, or
    :meth:`PaginatedReport.create_cache_refresh_plan`.

    Use :class:`~ssrs_library.Schedule` helpers to build a new schedule
    for :meth:`update`::

        plan.update(schedule=Schedule.weekly(["Monday", "Thursday"], hour=6))
    """

    def __init__(self, client: Any, data: Dict[str, Any]):
        self._client = client
        self._data = data

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def id(self) -> str:
        return self._data["Id"]

    @property
    def description(self) -> str:
        return self._data.get("Description", "")

    @property
    def event_type(self) -> str:
        return self._data.get("EventType", "")

    @property
    def catalog_item_path(self) -> Optional[str]:
        """Catalog path of the report this plan belongs to."""
        return self._data.get("CatalogItemPath")

    @property
    def schedule(self) -> Optional[Dict[str, Any]]:
        """
        Raw ``Schedule`` dict as returned by the API, containing a
        ``"Definition"`` key with ``"StartDateTime"``, ``"Recurrence"``, etc.
        """
        return self._data.get("Schedule")

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------

    def execute(self) -> None:
        """Trigger an immediate cache refresh."""
        self._client._request("POST", f"CacheRefreshPlans({self.id})/Execute")

    def update(
        self,
        description: Optional[str] = None,
        schedule: Optional[Union["Schedule", Dict[str, Any]]] = None,  # noqa: F821
    ) -> "CacheRefreshPlan":
        """
        Update the description and/or schedule of this plan.

        :param description: New human-readable description.
        :param schedule: A :class:`~ssrs_library.Schedule` instance
            **or** a raw schedule dict.

        Examples::

            plan.update(description="Updated label")

            plan.update(schedule=Schedule.daily(hour=4))

            plan.update(
                description="Bi-weekly on Fridays",
                schedule=Schedule.weekly(["Friday"], hour=22, interval=2),
            )
        """
        # Lazy import to avoid circular dependency.
        from ._schedule import Schedule as _Schedule

        payload = dict(self._data)
        if description is not None:
            payload["Description"] = description
        if schedule is not None:
            payload["Schedule"] = (
                schedule.to_api()
                if isinstance(schedule, _Schedule)
                else schedule
            )
        updated = self._client._request(
            "PUT", f"CacheRefreshPlans({self.id})", json=payload
        )
        self._data = updated or payload
        return self

    def delete(self) -> None:
        """Delete this cache-refresh plan."""
        self._client._request("DELETE", f"CacheRefreshPlans({self.id})")

    def __repr__(self) -> str:
        return (
            f"<CacheRefreshPlan id={self.id!r} "
            f"event={self.event_type!r} "
            f"description={self.description!r}>"
        )
