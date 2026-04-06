import base64
import logging
import os
from typing import Any, Dict, List, Optional
from urllib.parse import quote

import requests
from requests_ntlm import HttpNtlmAuth

from ._folder import Folder
from ._powerbi_report import PowerBIReport
from ._paginated_report import PaginatedReport
from .exceptions import PBIRSAuthError, PBIRSConflict, PBIRSError, PBIRSNotFound

logger = logging.getLogger(__name__)

# PBIX files larger than this threshold use multipart upload instead of base64.
_MULTIPART_THRESHOLD = 25 * 1024 * 1024  # 25 MB


class PBIRSClient:
    """
    Client for the Power BI Report Server REST API.

    :param base_url: Root URL of the web portal, e.g. ``"http://myserver/reports"``.
    :param username: Windows username for NTLM authentication.
    :param password: Windows password.
    :param domain: Windows domain (optional). When provided the credential is
        sent as ``DOMAIN\\username``.
    :param verify_ssl: Whether to verify TLS certificates (default ``True``).
        Set to ``False`` for self-signed certs in dev environments.
    :param timeout: HTTP request timeout in seconds (default ``30``).

    Basic usage::

        from ssrs_library import PBIRSClient

        client = PBIRSClient(
            "http://myserver/reports",
            username="svc_account",
            password="secret",
            domain="CORP",
        )

        report = client.get_powerbi_report("/Sales/Revenue Q1")
        for ds in report.get_datasources():
            print(ds.name, ds.connection_string)
    """

    def __init__(
        self,
        base_url: str,
        username: Optional[str] = None,
        password: Optional[str] = None,
        domain: Optional[str] = None,
        verify_ssl: bool = True,
        timeout: int = 30,
    ):
        self._base_url = base_url.rstrip("/")
        self._api_url = f"{self._base_url}/api/v2.0"
        self._verify_ssl = verify_ssl
        self._timeout = timeout

        self._session = requests.Session()
        if username and password:
            login = f"{domain}\\{username}" if domain else username
            self._session.auth = HttpNtlmAuth(login, password)

        self._session.headers.update({"Content-Type": "application/json"})

    # ------------------------------------------------------------------
    # Internal HTTP helpers
    # ------------------------------------------------------------------

    def _request(
        self, method: str, endpoint: str, **kwargs
    ) -> Optional[Dict[str, Any]]:
        """
        Send an authenticated request to the PBIRS REST API.

        Raises a typed :class:`PBIRSError` subclass on HTTP errors.
        Returns parsed JSON (or ``None`` for empty responses like 204).
        """
        url = f"{self._api_url}/{endpoint.lstrip('/')}"
        kwargs.setdefault("verify", self._verify_ssl)
        kwargs.setdefault("timeout", self._timeout)

        # Do not force application/json for multipart uploads.
        if "files" in kwargs and "headers" not in kwargs:
            kwargs["headers"] = {}

        logger.debug("%s %s", method, url)
        resp = self._session.request(method, url, **kwargs)

        if resp.status_code == 401:
            raise PBIRSAuthError("Authentication failed", status_code=401)
        if resp.status_code == 403:
            raise PBIRSAuthError("Access denied", status_code=403)
        if resp.status_code == 404:
            raise PBIRSNotFound(
                f"Resource not found: {endpoint}", status_code=404
            )
        if resp.status_code == 409:
            raise PBIRSConflict(
                f"Conflict: resource already exists at {endpoint}",
                status_code=409,
            )

        try:
            resp.raise_for_status()
        except requests.HTTPError as exc:
            raise PBIRSError(str(exc), status_code=resp.status_code) from exc

        if resp.status_code == 204 or not resp.content:
            return None

        content_type = resp.headers.get("Content-Type", "")
        if "application/json" in content_type:
            return resp.json()

        return None

    @staticmethod
    def _encode_path(path: str) -> str:
        """Normalise and percent-encode a catalog path for OData expressions."""
        if not path.startswith("/"):
            path = "/" + path
        return quote(path, safe="/")

    # ------------------------------------------------------------------
    # Connectivity
    # ------------------------------------------------------------------

    def test_connection(self) -> bool:
        """
        Return ``True`` when the server is reachable and credentials are valid.
        """
        try:
            self._request("GET", "System")
            return True
        except PBIRSError:
            return False

    # ------------------------------------------------------------------
    # Folders
    # ------------------------------------------------------------------

    def get_folder(self, path: str) -> Folder:
        """
        Return a :class:`Folder` handle for *path*.

        :raises PBIRSNotFound: when the folder does not exist.
        """
        encoded = self._encode_path(path)
        data = self._request("GET", f"Folders(Path='{encoded}')")
        return Folder(self, data)

    def create_folder(self, path: str, description: str = "") -> Folder:
        """
        Create a folder at *path* and return its handle.

        *path* must be absolute (e.g. ``"/Sales/2024"``).  The parent folder
        must already exist.

        :raises PBIRSConflict: when the folder already exists.
        """
        name = path.rstrip("/").split("/")[-1]
        parent = "/" + "/".join(path.strip("/").split("/")[:-1])

        payload = {
            "Name": name,
            "Path": path if path.startswith("/") else "/" + path,
            "Description": description,
        }
        if parent and parent != "/":
            payload["ParentFolderPath"] = parent

        data = self._request("POST", "Folders", json=payload)
        return Folder(self, data)

    def list_folders(self, parent_path: str = "/") -> List[Folder]:
        """
        Return the direct sub-folders of *parent_path*.

        Uses the parent folder's ``CatalogItems`` endpoint filtered by type,
        so only the immediate children are returned (non-recursive).
        """
        folder = self.get_folder(parent_path)
        items = self._request(
            "GET", f"Folders({folder.id})/CatalogItems"
        ) or {}
        return [
            Folder(self, item)
            for item in items.get("value", [])
            if item.get("Type") == "Folder"
        ]

    # ------------------------------------------------------------------
    # Power BI reports
    # ------------------------------------------------------------------

    def get_powerbi_report(self, path: str) -> PowerBIReport:
        """
        Return a :class:`PowerBIReport` handle for the report at *path*.

        :raises PBIRSNotFound: when the report does not exist.
        """
        encoded = self._encode_path(path)
        data = self._request("GET", f"PowerBIReports(Path='{encoded}')")
        return PowerBIReport(self, data)

    def list_powerbi_reports(
        self, folder_path: Optional[str] = None
    ) -> List[PowerBIReport]:
        """
        List Power BI reports.

        :param folder_path: When given, only return reports inside that folder
            (direct children only, not recursive).  When omitted, return all
            reports in the catalog.
        """
        if folder_path is not None:
            folder = self.get_folder(folder_path)
            items = self._request(
                "GET", f"Folders({folder.id})/CatalogItems"
            ) or {}
            return [
                PowerBIReport(self, item)
                for item in items.get("value", [])
                if item.get("Type") == "PowerBIReport"
            ]

        data = self._request("GET", "PowerBIReports") or {}
        return [PowerBIReport(self, item) for item in data.get("value", [])]

    def upload_powerbi_report(
        self,
        folder_path: str,
        file_path: str,
        name: Optional[str] = None,
        overwrite: bool = False,
    ) -> PowerBIReport:
        """
        Upload a ``.pbix`` file to *folder_path*.

        :param folder_path: Destination catalog folder (e.g. ``"/Sales"``).
        :param file_path: Local path to the ``.pbix`` file.
        :param name: Catalog name for the report.  Defaults to the filename
            without extension.
        :param overwrite: Replace an existing report with the same name.
        :returns: A :class:`PowerBIReport` handle for the uploaded report.
        :raises PBIRSConflict: when a report already exists and
            *overwrite* is ``False``.
        """
        if name is None:
            name = os.path.splitext(os.path.basename(file_path))[0]

        folder_path = "/" + folder_path.strip("/")

        with open(file_path, "rb") as fh:
            content = fh.read()

        if len(content) > _MULTIPART_THRESHOLD:
            data = self._upload_pbix_multipart(
                name, folder_path, content, overwrite
            )
        else:
            data = self._upload_pbix_base64(name, folder_path, content, overwrite)

        return PowerBIReport(self, data)

    def _upload_pbix_multipart(
        self,
        name: str,
        folder_path: str,
        content: bytes,
        overwrite: bool,
    ) -> Dict[str, Any]:
        params = {
            "@Name": name,
            "@Path": folder_path,
            "@Overwrite": str(overwrite).lower(),
        }
        files = {"file": (f"{name}.pbix", content, "application/octet-stream")}
        # Remove the default Content-Type header so requests sets it for multipart.
        headers = {k: v for k, v in self._session.headers.items()
                   if k.lower() != "content-type"}
        resp = self._session.post(
            f"{self._api_url}/PowerBIReports",
            params=params,
            files=files,
            headers=headers,
            verify=self._verify_ssl,
            timeout=self._timeout,
        )
        try:
            resp.raise_for_status()
        except requests.HTTPError as exc:
            raise PBIRSError(str(exc), status_code=resp.status_code) from exc
        return resp.json()

    def _upload_pbix_base64(
        self,
        name: str,
        folder_path: str,
        content: bytes,
        overwrite: bool,
    ) -> Dict[str, Any]:
        payload = {
            "@odata.type": "#Model.PowerBIReport",
            "Content": base64.b64encode(content).decode("utf-8"),
            "ContentType": "application/octet-stream",
            "Name": name,
            "Path": folder_path,
            "Description": "",
        }
        if overwrite:
            # Fetch existing report to get its ID and PATCH it.
            target_path = f"{folder_path}/{name}"
            try:
                existing = self.get_powerbi_report(target_path)
                data = self._request(
                    "PATCH", f"PowerBIReports({existing.id})", json=payload
                )
                return data or existing._data
            except PBIRSNotFound:
                pass  # Fall through to POST.

        data = self._request("POST", "PowerBIReports", json=payload)
        return data

    # ------------------------------------------------------------------
    # Paginated (SSRS) reports
    # ------------------------------------------------------------------

    def get_paginated_report(self, path: str) -> PaginatedReport:
        """
        Return a :class:`PaginatedReport` handle for the report at *path*.

        :raises PBIRSNotFound: when the report does not exist.
        """
        encoded = self._encode_path(path)
        data = self._request("GET", f"Reports(Path='{encoded}')")
        return PaginatedReport(self, data)

    def list_paginated_reports(
        self, folder_path: Optional[str] = None
    ) -> List[PaginatedReport]:
        """
        List paginated (SSRS) reports.

        :param folder_path: When given, only return reports inside that folder
            (direct children only, not recursive).  When omitted, return all
            paginated reports in the catalog.
        """
        if folder_path is not None:
            folder = self.get_folder(folder_path)
            items = self._request(
                "GET", f"Folders({folder.id})/CatalogItems"
            ) or {}
            return [
                PaginatedReport(self, item)
                for item in items.get("value", [])
                if item.get("Type") == "Report"
            ]

        data = self._request("GET", "Reports") or {}
        return [PaginatedReport(self, item) for item in data.get("value", [])]

    def upload_paginated_report(
        self,
        folder_path: str,
        file_path: str,
        name: Optional[str] = None,
        overwrite: bool = False,
    ) -> PaginatedReport:
        """
        Upload a ``.rdl`` file to *folder_path*.

        :param folder_path: Destination catalog folder (e.g. ``"/Finance"``).
        :param file_path: Local path to the ``.rdl`` file.
        :param name: Catalog name for the report.  Defaults to the filename
            without extension.
        :param overwrite: Replace an existing report with the same name.
        :returns: A :class:`PaginatedReport` handle for the uploaded report.
        :raises PBIRSConflict: when a report already exists and
            *overwrite* is ``False``.
        """
        if name is None:
            name = os.path.splitext(os.path.basename(file_path))[0]

        folder_path = "/" + folder_path.strip("/")

        with open(file_path, "rb") as fh:
            content = fh.read()

        payload = {
            "@odata.type": "#Model.Report",
            "Content": base64.b64encode(content).decode("utf-8"),
            "ContentType": "application/octet-stream",
            "Name": name,
            "Path": folder_path,
            "Description": "",
        }

        if overwrite:
            target_path = f"{folder_path}/{name}"
            try:
                existing = self.get_paginated_report(target_path)
                data = self._request(
                    "PATCH", f"Reports({existing.id})", json=payload
                )
                return PaginatedReport(self, data or existing._data)
            except PBIRSNotFound:
                pass  # Fall through to POST.

        data = self._request("POST", "Reports", json=payload)
        return PaginatedReport(self, data)

    def __repr__(self) -> str:
        return f"<PBIRSClient url={self._base_url!r}>"
