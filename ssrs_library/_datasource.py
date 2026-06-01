import copy
from typing import Any, Dict, Optional


class DataSource:
    """
    Represents a report data source.

    Build one via :meth:`DataSource.from_api` (round-trip from the server)
    or construct it manually for :meth:`~PowerBIReport.set_datasources` /
    :meth:`~PaginatedReport.set_datasources` calls::

        ds = DataSource(
            name="MyDB",
            connection_string="Data Source=srv;Initial Catalog=db",
            data_source_type="SQL",
            credential_retrieval="Store",
            username="svc",
            password="secret",
            windows_credentials=True,
        )
    """

    def __init__(
        self,
        name: str,
        connection_string: str,
        data_source_type: str = "SQL",
        enabled: bool = True,
        id: Optional[str] = None,
        description: Optional[str] = None,
        # Credential retrieval: "None" | "Prompt" | "Store" | "Integrated"
        credential_retrieval: str = "None",
        username: Optional[str] = None,
        password: Optional[str] = None,
        windows_credentials: bool = True,
        # "DataModel" for Power BI (.pbix) datasources, None for paginated (.rdl)
        data_source_sub_type: Optional[str] = None,
    ):
        self.id = id
        self.name = name
        self.description = description
        self.connection_string = connection_string
        self.data_source_type = data_source_type
        self.enabled = enabled
        self.credential_retrieval = credential_retrieval
        self.username = username
        self.password = password
        self.windows_credentials = windows_credentials
        self.data_source_sub_type = data_source_sub_type
        self._raw: Optional[Dict[str, Any]] = None

    # ------------------------------------------------------------------
    # Serialisation helpers
    # ------------------------------------------------------------------

    @classmethod
    def from_api(cls, data: Dict[str, Any]) -> "DataSource":
        sub_type = data.get("DataSourceSubType")

        if sub_type == "DataModel":
            dm = data.get("DataModelDataSource") or {}
            auth_type = dm.get("AuthType", "Windows")
            # Key auth has no username/password pair in the traditional sense
            win_creds = auth_type in ("Windows", "Impersonate")
            cred_retrieval = "None" if auth_type == "Key" else "Store"
            instance = cls(
                id=data.get("Id"),
                name=data.get("Name", ""),
                description=data.get("Description"),
                connection_string=data.get("ConnectionString", ""),
                data_source_type=data.get("DataSourceType", ""),
                enabled=data.get("Enabled", True),
                credential_retrieval=cred_retrieval,
                username=dm.get("Username"),
                password=dm.get("Secret"),
                windows_credentials=win_creds,
                data_source_sub_type="DataModel",
            )
            instance._raw = data
            return instance

        # Standard paginated-report / shared-dataset datasource
        cred_retrieval = data.get("CredentialRetrieval", "None")
        cred_in_server = data.get("CredentialsInServer") or {}
        instance = cls(
            id=data.get("Id"),
            name=data.get("Name", ""),
            description=data.get("Description"),
            connection_string=data.get("ConnectionString", ""),
            data_source_type=data.get("DataSourceType", "SQL"),
            enabled=data.get("Enabled", True),
            credential_retrieval=cred_retrieval,
            username=cred_in_server.get("UserName"),
            password=cred_in_server.get("Password"),
            windows_credentials=cred_in_server.get("WindowsCredentials", True),
        )
        instance._raw = data
        return instance

    def to_api(self) -> Dict[str, Any]:
        if self.data_source_sub_type == "DataModel":
            # Start from the full server payload so no required fields are dropped.
            # AuthType: Windows (stored Windows creds) or UsernamePassword (SQL/Basic)
            auth_type = "Windows" if self.windows_credentials else "UsernamePassword"
            payload: Dict[str, Any] = copy.deepcopy(self._raw) if self._raw else {}
            payload.update({
                "Name": self.name,
                "ConnectionString": self.connection_string,
                "DataSourceType": self.data_source_type,
                "DataSourceSubType": "DataModel",
                "Enabled": self.enabled,
            })
            if self.id:
                payload["Id"] = self.id
            # Merge credential changes into the DataModelDataSource sub-object,
            # preserving any extra fields the server originally returned.
            base_dm: Dict[str, Any] = copy.deepcopy(
                (self._raw or {}).get("DataModelDataSource") or {}
            )
            base_dm.update({
                "AuthType": auth_type,
                "Username": self.username,
                "Secret": self.password,
            })
            payload["DataModelDataSource"] = base_dm
            return payload

        # Standard paginated-report format (PUT/PATCH)
        # Start from the full server payload so no required fields are dropped.
        payload = copy.deepcopy(self._raw) if self._raw else {}
        payload.update({
            "Name": self.name,
            "ConnectionString": self.connection_string,
            "DataSourceType": self.data_source_type,
            "Enabled": self.enabled,
            "CredentialRetrieval": self.credential_retrieval,
        })
        if self.id:
            payload["Id"] = self.id
        if self.description is not None:
            payload["Description"] = self.description
        if self.credential_retrieval == "Store" and self.username is not None:
            payload["CredentialsInServer"] = {
                "UserName": self.username,
                "Password": self.password,
                "WindowsCredentials": self.windows_credentials,
            }
        else:
            payload.pop("CredentialsInServer", None)
        return payload

    def __repr__(self) -> str:
        return (
            f"<DataSource name={self.name!r} type={self.data_source_type!r} "
            f"credentials={self.credential_retrieval!r}>"
        )
