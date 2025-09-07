"""
SSRS Python Library - A Python replacement for ReportingServicesTools PowerShell module
"""

import requests
from requests_ntlm import HttpNtlmAuth
from urllib.parse import urljoin, quote
import json
import logging
from typing import Dict, List, Optional, Union, Any
import os
import base64
import uuid
import xml.etree.ElementTree as ET
from pathlib import Path

# Import types
from .types.rsitemtype import RsItemType
from .types.datasourcetype import DataSourceType
from .types.rscredentials import (
    RsCredentials,
    CredentialsByUser,
    CredentialsInServer,
    NoCredentials,
)
from .types.rsdatasource import RsDataSource
from .types.rsitem import RsItem, RsFolder

# Import datasource logic
from .datasource_manager import SSRSDataSourceManager

# Configure logging
logging.basicConfig(level=logging.WARNING)
logger = logging.getLogger(__name__)


class SSRSRestClient:
    """
    SSRS REST API Client - Main class for interacting with SSRS REST endpoints
    """

    def __init__(
        self,
        server_url: str,
        username: str = None,
        password: str = None,
        domain: str = None,
        verify_ssl: bool = True,
        timeout: int = 3600,
    ):
        """
        Initialize SSRS REST client

        Args:
            server_url: SSRS server URL (e.g., 'http://myserver/reports')
            username: Username for NTLM authentication
            password: Password for NTLM authentication
            domain: Domain for NTLM authentication
            verify_ssl: Whether to verify SSL certificates
            timeout: Request timeout in seconds
        """
        self.server_url = server_url.rstrip("/")
        self.api_base = f"{self.server_url}/api/v2.0"
        self.verify_ssl = verify_ssl
        self.timeout = timeout

        # Setup authentication
        if username and password:
            if domain:
                auth_user = f"{domain}\\{username}"
            else:
                auth_user = username
            self.auth = HttpNtlmAuth(auth_user, password)
        else:
            self.auth = None

        # Setup session
        self.session = requests.Session()
        if self.auth:
            self.session.auth = self.auth
        self.session.verify = verify_ssl

        # Common headers
        self.session.headers.update(
            {"Content-Type": "application/json", "Accept": "application/json"}
        )

    def _make_request(self, method: str, endpoint: str, **kwargs) -> requests.Response:
        """
        Make HTTP request to SSRS REST API

        Args:
            method: HTTP method (GET, POST, PUT, DELETE)
            endpoint: API endpoint (without base URL)
            **kwargs: Additional arguments for requests

        Returns:
            Response object

        Raises:
            requests.RequestException: If request fails
        """
        url = urljoin(self.api_base + "/", endpoint.lstrip("/"))

        try:
            response = self.session.request(
                method=method,
                url=url,
                timeout=self.timeout,
                verify=self.verify_ssl,
                **kwargs,
            )

            logger.debug(f"{method} {url} - Status: {response.status_code}")

            # Raise exception for HTTP errors
            response.raise_for_status()

            return response

        except requests.RequestException as e:
            logger.error(f"Request failed: {method} {url} - {str(e)}")
            raise

    def _get_catalog_item_path(self, path: str) -> str:
        """
        Format catalog item path for API calls

        Args:
            path: Item path (e.g., '/MyFolder/MyReport')

        Returns:
            Formatted path for API
        """
        if not path.startswith("/"):
            path = "/" + path
        return quote(path, safe="/")

    def delete_catalog_item(self, path: str) -> bool:
        """
        Delete a catalog item by path
        Args:
            path: Path to the catalog item (e.g., '/MyFolder/MyReport')

        Returns:
            True if deletion was successful, False otherwise
        """
        formatted_path = self._get_catalog_item_path(path)
        endpoint = f"CatalogItems(Path='{formatted_path}')"
        try:
            response = self._make_request("DELETE", endpoint)
            if response.status_code == 204:
                logger.info(f"Catalog item {path} deleted successfully")
                return True
            else:
                logger.error(
                    f"Failed to delete catalog item {path}: {response.status_code} - {response.text}"
                )
                return False
        except requests.RequestException as e:
            logger.error(f"Error deleting catalog item {path}: {str(e)}")
            return False

    def get_catalog_item(self, path: str) -> RsItem:
        """
        Get catalog item information

        Args:
            path: Path to the catalog item

        Returns:
            RsItem object with item information
        """
        formatted_path = self._get_catalog_item_path(path)
        endpoint = f"CatalogItems(Path='{formatted_path}')"

        response = self._make_request("GET", endpoint)
        data = response.json()

        return RsItem(
            name=data.get("Name"),
            path=data.get("Path"),
            item_type=RsItemType(data.get("Type")),
            id=data.get("Id"),
            description=data.get("Description"),
            hidden=data.get("Hidden", False),
            size=data.get("Size"),
            created_date=data.get("CreationDate"),
            modified_date=data.get("ModificationDate"),
            created_by=data.get("CreatedBy"),
            modified_by=data.get("ModifiedBy"),
        )

    def create_folder(self, folder: RsFolder) -> bool:
        """
        Create a new folder in the SSRS catalog
        
        Args:
            folder: RsFolder object with folder details

        Returns:
            True if folder was created successfully, False otherwise
        """
        endpoint = "Folders"
        payload = {
            "@odata.type": "#Model.Folder",
            "Name": folder.name,
            "Path": folder.path,
            "Description": folder.description or "",
            "Hidden": folder.hidden,
        }
        if folder.id:
            payload["Id"] = folder.id

        # Check if folder already exists
        try:
            self.get_catalog_item(folder.path)
            logger.info(f"Folder {folder.path} already exists.")
            return False
        except requests.RequestException:
            # Folder does not exist, proceed to create
            pass

        try:
            response = self._make_request("POST", endpoint, json=payload)
            if response.status_code == 201:
                logger.info(
                    f"Folder {folder.name} created successfully at {folder.path}"
                )
                return True
            else:
                logger.error(
                    f"Failed to create folder {folder.name}: {response.status_code} - {response.text}"
                )
                return False
        except requests.RequestException as e:
            logger.error(f"Error creating folder {folder.name}: {str(e)}")
            return False

    def delete_folder(self, path: str) -> bool:
        """
        Delete a folder and its contents

        Args:
            path: Path to the folder (e.g., '/MyFolder')

        Returns:
            True if deletion was successful, False otherwise
        """
        formatted_path = self._get_catalog_item_path(path)
        endpoint = f"Folders(Path='{formatted_path}')"
        try:
            response = self._make_request("DELETE", endpoint)
            if response.status_code == 204:
                logger.info(f"Folder {path} deleted successfully")
                return True
            else:
                logger.error(
                    f"Failed to delete folder {path}: {response.status_code} - {response.text}"
                )
                return False
        except requests.RequestException as e:
            logger.error(f"Error deleting folder {path}: {str(e)}")
            return False

    def get_catalog_items(self, folder_path: str = "/") -> List[RsItem]:
        """
        Get catalog items in a folder

        Args:
            folder_path: Path to the folder (default: root '/')

        Returns:
            List of RsItem objects
        """
        formatted_path = self._get_catalog_item_path(folder_path)
        endpoint = f"Folders(Path='{formatted_path}')/CatalogItems?`$expand=Properties"

        response = self._make_request("GET", endpoint)
        data = response.json()

        items = []
        for item_data in data.get("value", []):
            items.append(
                RsItem(
                    name=item_data.get("Name"),
                    path=item_data.get("Path"),
                    item_type=RsItemType(item_data.get("Type")),
                    id=item_data.get("Id"),
                    description=item_data.get("Description"),
                    hidden=item_data.get("Hidden", False),
                    size=item_data.get("Size"),
                    created_date=item_data.get("CreationDate"),
                    modified_date=item_data.get("ModificationDate"),
                    created_by=item_data.get("CreatedBy"),
                    modified_by=item_data.get("ModifiedBy"),
                )
            )

        return items

    def upload_catalog_item(
        self,
        file_path: str,
        rs_folder: str,
        description: str = "",
        overwrite: bool = False,
        hidden: bool = False,
        max_file_size_mb: float = 2000,
        min_large_file_size_mb: float = 25,
    ) -> bool:
        """
        Upload catalog item to SSRS server (equivalent to Write-RsRestCatalogItem)

        Args:
            file_path: Path to the file to upload
            rs_folder: Target folder on the SSRS server
            description: Description for the item
            overwrite: Whether to overwrite existing items
            hidden: Whether to mark the item as hidden
            max_file_size_mb: Maximum file size in MB
            min_large_file_size_mb: Minimum size to treat as large file

        Returns:
            True if successful, False otherwise
        """

        try:
            if not os.path.exists(file_path):
                raise FileNotFoundError(
                    f"No item found at the specified path: {file_path}"
                )

            file_path_obj = Path(file_path)
            item_name = file_path_obj.stem  # Name without extension
            file_extension = file_path_obj.suffix.lower()
            full_item_name = file_path_obj.name  # Full name with extension

            # Determine item type based on extension
            item_type = self._get_item_type_from_extension(file_extension)

            # For resources and excel workbooks, preserve the extension
            if item_type in ["Resource", "ExcelWorkbook"]:
                item_name = full_item_name

            # Construct item path
            if rs_folder == "/":
                item_path = f"/{item_name}"
            else:
                item_path = f"{rs_folder.rstrip('/')}/{item_name}"

            logger.info(f"Uploading {file_path} to {rs_folder}...")

            # Handle different file types
            if item_type == "DataSource":
                return self._upload_data_source(
                    file_path, file_extension, item_name, item_path, hidden
                )
            elif item_type == "Kpi":
                return self._upload_kpi(file_path, item_path, hidden)
            else:
                return self._upload_regular_item(
                    file_path,
                    item_type,
                    item_name,
                    item_path,
                    description,
                    hidden,
                    overwrite,
                    max_file_size_mb,
                    min_large_file_size_mb,
                )

        except Exception as e:
            logger.error(f"Failed to upload catalog item: {str(e)}")
            return False

    def _get_item_type_from_extension(self, extension: str) -> str:
        """
        Get SSRS item type from file extension
        """
        extension_map = {
            ".rdl": "Report",
            ".rdlc": "Report",
            ".rds": "DataSource",
            ".rsds": "DataSource",
            ".rsd": "DataSet",
            ".pbix": "PowerBIReport",
            ".xlsx": "ExcelWorkbook",
            ".xls": "ExcelWorkbook",
            ".json": "Kpi",  # For KPI files
            ".jpg": "Resource",
            ".jpeg": "Resource",
            ".png": "Resource",
            ".gif": "Resource",
            ".pdf": "Resource",
            ".txt": "Resource",
            ".xml": "Resource",
            ".css": "Resource",
            ".js": "Resource",
        }

        return extension_map.get(extension, "Resource")

    def _upload_data_source(
        self,
        file_path: str,
        extension: str,
        item_name: str,
        item_path: str,
        hidden: bool,
    ) -> bool:
        """
        Upload data source file (.rds or .rsds)
        """

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()

            root = ET.fromstring(content)

            if extension == ".rsds":
                # Handle .rsds format
                if root.tag != "DataSourceDefinition":
                    raise ValueError("Invalid .rsds data source file format")

                connection_string = (
                    root.find("ConnectString").text
                    if root.find("ConnectString") is not None
                    else ""
                )
                data_source_type = (
                    root.find("Extension").text
                    if root.find("Extension") is not None
                    else ""
                )
                enabled = (
                    root.find("Enabled").text.lower() == "true"
                    if root.find("Enabled") is not None
                    else True
                )

            elif extension == ".rds":
                # Handle .rds format
                if root.tag != "RptDataSource":
                    raise ValueError("Invalid .rds data source file format")

                name_elem = root.find("Name")
                if name_elem is not None:
                    item_name = name_elem.text
                    # Update item_path with actual name from file
                    item_path = item_path.rsplit("/", 1)[0] + "/" + item_name

                conn_props = root.find("ConnectionProperties")
                if conn_props is None:
                    raise ValueError("ConnectionProperties not found in .rds file")

                connection_string = (
                    conn_props.find("ConnectString").text
                    if conn_props.find("ConnectString") is not None
                    else ""
                )
                data_source_type = (
                    conn_props.find("Extension").text
                    if conn_props.find("Extension") is not None
                    else ""
                )
                enabled = True

                # Handle credentials
                credential_retrieval = "None"
                prompt = None

                if conn_props.find("Prompt") is not None:
                    credential_retrieval = "Prompt"
                    prompt = conn_props.find("Prompt").text
                elif (
                    conn_props.find("IntegratedSecurity") is not None
                    and conn_props.find("IntegratedSecurity").text.lower() == "true"
                ):
                    credential_retrieval = "Integrated"

            # Build payload for data source
            payload = {
                "@odata.type": "#Model.DataSource",
                "Path": item_path,
                "Name": item_name,
                "Description": "",
                "DataSourceType": data_source_type,
                "ConnectionString": connection_string,
                "CredentialRetrieval": credential_retrieval,
                "CredentialsByUser": None,
                "CredentialsInServer": None,
                "Hidden": hidden,
                "IsConnectionStringOverridden": True,
                "IsEnabled": enabled,
            }

            if credential_retrieval == "Prompt" and prompt:
                payload["CredentialsByUser"] = {
                    "DisplayText": prompt,
                    "UseAsWindowsCredentials": True,
                }

            # Upload data source
            endpoint = "CatalogItems"
            response = self._make_request("POST", endpoint, json=payload)

            logger.info(f"Data source {item_name} uploaded successfully to {item_path}")
            return True

        except Exception as e:
            logger.error(f"Failed to upload data source: {str(e)}")
            return False

    def _upload_kpi(self, file_path: str, item_path: str, hidden: bool) -> bool:
        """
        Upload KPI file (.json)
        """
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                payload = json.load(f)

            payload["Path"] = item_path
            if hidden:
                payload["Hidden"] = hidden

            endpoint = "CatalogItems"
            response = self._make_request("POST", endpoint, json=payload)

            logger.info(f"KPI uploaded successfully to {item_path}")
            return True

        except Exception as e:
            logger.error(f"Failed to upload KPI: {str(e)}")
            return False

    def _upload_regular_item(
        self,
        file_path: str,
        item_type: str,
        item_name: str,
        item_path: str,
        description: str,
        hidden: bool,
        overwrite: bool,
        max_file_size_mb: float,
        min_large_file_size_mb: float,
    ) -> bool:
        """
        Upload regular catalog items (reports, resources, etc.)
        """

        try:
            file_size_mb = os.path.getsize(file_path) / (1024 * 1024)

            # Check if it's a large PowerBI report
            is_large_powerbi_report = (
                item_type == "PowerBIReport" and file_size_mb >= min_large_file_size_mb
            )

            if is_large_powerbi_report:
                # Validate file size limits
                if file_size_mb > max_file_size_mb:
                    raise ValueError(
                        f"File is too large. Files larger than {max_file_size_mb} MB are not supported"
                    )

                # Get server file size limit
                try:
                    server_limit = self._get_server_file_size_limit()
                    if server_limit > 0 and file_size_mb > server_limit:
                        raise ValueError(
                            f"File is too large. Server limit is {server_limit} MB"
                        )
                except:
                    logger.warning("Could not retrieve server file size limit")

                logger.info(
                    f"PowerBI Report {item_name} is large. Properties Overwrite, Description, and Hidden are being ignored"
                )

                return self._upload_large_powerbi_report(
                    file_path, item_name, item_path
                )
            else:
                return self._upload_small_item(
                    file_path,
                    item_type,
                    item_name,
                    item_path,
                    description,
                    hidden,
                    overwrite,
                )

        except Exception as e:
            logger.error(f"Failed to upload regular item: {str(e)}")
            return False

    def _upload_large_powerbi_report(
        self, file_path: str, item_name: str, item_path: str
    ) -> bool:
        """
        Upload large PowerBI report using multipart form data
        """

        try:
            # Read file as binary
            with open(file_path, "rb") as f:
                file_content = f.read()

            # Convert to ISO-8859-1 encoding for multipart
            file_content_str = file_content.decode("iso-8859-1")

            # Create multipart boundary
            boundary = str(uuid.uuid4())

            # Build multipart body
            body_parts = [
                f"--{boundary}",
                f'Content-Disposition: form-data; name="File"; filename="{item_name}"',
                "Content-Type: application/octet-stream",
                "",
                file_content_str,
                f"--{boundary}--",
            ]

            body = "\r\n".join(body_parts)

            # Upload using special endpoint for large files
            endpoint = f"PowerBIReports(Path='{item_path}')/Model.Upload"

            headers = {"Content-Type": f"multipart/form-data; boundary={boundary}"}

            # Temporarily update session headers
            original_headers = self.session.headers.copy()
            self.session.headers.update(headers)

            try:
                response = self.session.post(
                    url=f"{self.api_base}/{endpoint}",
                    data=body.encode("iso-8859-1"),
                    timeout=self.timeout,
                    verify=self.verify_ssl,
                )
                response.raise_for_status()

                logger.info(
                    f"Large PowerBI report uploaded successfully to {item_path}"
                )
                return True

            finally:
                # Restore original headers
                self.session.headers = original_headers

        except Exception as e:
            logger.error(f"Failed to upload large PowerBI report: {str(e)}")
            return False

    def _upload_small_item(
        self,
        file_path: str,
        item_type: str,
        item_name: str,
        item_path: str,
        description: str,
        hidden: bool,
        overwrite: bool,
    ) -> bool:
        """
        Upload small catalog item using JSON payload
        """

        try:
            # Read file content and encode as base64
            with open(file_path, "rb") as f:
                file_content = f.read()

            content_base64 = base64.b64encode(file_content).decode("utf-8")

            # Build payload
            payload = {
                "@odata.type": f"#Model.{item_type}",
                "Content": content_base64,
                "ContentType": "",
                "Name": item_name,
                "Description": description,
                "Path": item_path,
                "Hidden": hidden,
            }

            # Try to upload
            try:
                endpoint = "CatalogItems"
                response = self._make_request("POST", endpoint, json=payload)

                logger.info(f"Item uploaded successfully to {item_path}")
                return True

            except requests.RequestException as e:
                # Handle conflict (409) if overwrite is enabled
                if (
                    hasattr(e, "response")
                    and e.response is not None
                    and e.response.status_code == 409
                    and overwrite
                ):

                    logger.info(
                        f"{item_name} already exists at {item_path}. Attempting to overwrite..."
                    )
                    return self._overwrite_item(item_path, payload)
                else:
                    raise

        except Exception as e:
            logger.error(f"Failed to upload small item: {str(e)}")
            return False

    def _overwrite_item(self, item_path: str, payload: dict) -> bool:
        """
        Overwrite existing catalog item
        """
        try:
            # Get existing item to retrieve its ID
            formatted_path = self._get_catalog_item_path(item_path)
            endpoint = f"CatalogItems(Path='{formatted_path}')"

            response = self._make_request("GET", endpoint)
            item_info = response.json()
            item_id = item_info["Id"]

            logger.info(f"Overwriting item at {item_path}...")

            # Update existing item
            endpoint = f"CatalogItems({item_id})"
            response = self._make_request("PUT", endpoint, json=payload)

            logger.info(f"Item overwritten successfully at {item_path}")
            return True

        except Exception as e:
            logger.error(f"Failed to overwrite item: {str(e)}")
            return False

    def _get_server_file_size_limit(self) -> float:
        """
        Get server file size limit setting
        """
        try:
            endpoint = "System/Properties"
            response = self._make_request("GET", endpoint)
            properties = response.json()

            for prop in properties.get("Properties", []):
                if prop.get("Name") == "MaxFileSizeMb":
                    return float(prop.get("Value", 0))

            return 0  # No limit found

        except:
            return 0  # Error getting limit

    def test_connection(self) -> bool:
        """
        Test connection to SSRS server

        Returns:
            True if connection successful, False otherwise
        """
        try:
            response = self._make_request("GET", "")
            return response.status_code == 200
        except requests.RequestException:
            return False
