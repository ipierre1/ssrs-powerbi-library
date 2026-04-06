from typing import Any, Dict, List, TYPE_CHECKING

if TYPE_CHECKING:
    from .client import PBIRSClient
    from ._powerbi_report import PowerBIReport
    from ._paginated_report import PaginatedReport


class Folder:
    """
    Handle on a PBIRS catalog folder.

    Obtained via :meth:`PBIRSClient.get_folder` or
    :meth:`PBIRSClient.create_folder`::

        folder = client.get_folder("/Sales/2024")
        for item in folder.list_items():
            print(item["Name"], item["Type"])
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

    # ------------------------------------------------------------------
    # Listing children
    # ------------------------------------------------------------------

    def list_items(self) -> List[Dict[str, Any]]:
        """Return raw catalog items (all types) contained in this folder."""
        data = self._client._request("GET", f"Folders({self.id})/CatalogItems")
        return data.get("value", [])

    def list_powerbi_reports(self) -> List["PowerBIReport"]:
        """Return PowerBI reports directly inside this folder."""
        return self._client.list_powerbi_reports(self.path)

    def list_paginated_reports(self) -> List["PaginatedReport"]:
        """Return paginated (SSRS) reports directly inside this folder."""
        return self._client.list_paginated_reports(self.path)

    def list_folders(self) -> List["Folder"]:
        """Return sub-folders directly inside this folder."""
        return self._client.list_folders(self.path)

    # ------------------------------------------------------------------
    # Security policies (catalog-level access control)
    # ------------------------------------------------------------------

    def get_policies(self) -> Dict[str, Any]:
        """
        Return the security policies on this folder.

        The returned dict has two keys:

        * ``"InheritParentSecurity"`` (*bool*) — whether the folder inherits
          its parent's policy instead of defining its own.
        * ``"Policies"`` (*list*) — each entry is
          ``{"GroupUserName": "CORP\\\\name", "Roles": [{"RoleName": "Browser"}]}``.

        Built-in role names: ``"Browser"``, ``"Content Manager"``,
        ``"Publisher"``, ``"Report Builder"``, ``"My Reports"``.
        """
        data = self._client._request("GET", f"Folders({self.id})/Policies")
        return data or {"InheritParentSecurity": False, "Policies": []}

    def set_policies(self, policy_data: Dict[str, Any]) -> None:
        """
        Replace the security policies on this folder (full overwrite).

        :param policy_data: Dict as returned by :meth:`get_policies`.

        Example — grant two users access and stop inheriting parent::

            policies = folder.get_policies()
            policies["InheritParentSecurity"] = False
            policies["Policies"] = [
                {"GroupUserName": "CORP\\\\alice",  "Roles": [{"RoleName": "Browser"}]},
                {"GroupUserName": "CORP\\\\admins", "Roles": [{"RoleName": "Content Manager"}]},
            ]
            folder.set_policies(policies)
        """
        self._client._request("PUT", f"Folders({self.id})/Policies", json=policy_data)

    def add_user(self, username: str, roles: List[str]) -> None:
        """
        Grant *username* the specified catalog *roles* on this folder.

        Uses a read-modify-write pattern: existing entries for other users
        are preserved, and if *username* already appears their roles are
        merged (no duplicates).

        :param username: Domain-qualified name, e.g. ``"CORP\\\\alice"``
            or a group like ``"CORP\\\\Sales Team"``.
        :param roles: List of role-name strings, e.g. ``["Browser"]`` or
            ``["Content Manager", "Publisher"]``.

        Example::

            folder.add_user("CORP\\\\alice", ["Browser"])
            folder.add_user("CORP\\\\admins", ["Content Manager"])
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
        Remove *username* from all security policies on this folder.

        Uses a read-modify-write pattern.  If *username* is not present
        this is a no-op.

        :param username: Domain-qualified name, e.g. ``"CORP\\\\alice"``.
        """
        data = self.get_policies()
        data["Policies"] = [
            p for p in data.get("Policies", [])
            if p.get("GroupUserName", "").lower() != username.lower()
        ]
        self.set_policies(data)

    # ------------------------------------------------------------------
    # Mutation
    # ------------------------------------------------------------------

    def delete(self) -> None:
        """Delete this folder and all its content."""
        self._client._request("DELETE", f"Folders({self.id})")

    def __repr__(self) -> str:
        return f"<Folder name={self.name!r} path={self.path!r}>"
