import requests
import logging

from typing import List, Dict


from .types.rsdatasource import RsDataSource
from .types.datasourcetype import DataSourceType
from .types.rsitem import RsItem
from .types.rsitemtype import RsItemType
from .types.rscredentials import CredentialsByUser, CredentialsInServer, NoCredentials

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class SSRSDataSourceManager:
    """
    Manager class for SSRS Data Source operations
    """

    def __init__(self, client):
        # Import here to avoid circular import
        from .ssrs_library import SSRSRestClient

        if not isinstance(client, SSRSRestClient):
            raise TypeError("client must be an instance of SSRSRestClient")
        """
        Initialize data source manager
        
        Args:
            client: SSRSRestClient instance
        """
        self.client = client

    def get_item_data_sources(self, item_path: str) -> List[RsDataSource]:
        """
        Get data sources for a catalog item (Report, Dataset, etc.)

        Args:
            item_path: Path to the catalog item

        Returns:
            List of RsDataSource objects
        """
        formatted_path = self.client._get_catalog_item_path(item_path)
        endpoint = (
            f"CatalogItems(Path='{formatted_path}')?&$expand=DataSources,Properties"
        )

        try:
            response = self.client._make_request("GET", endpoint)
            data = response.json()

            data_sources = []
            for ds_data in data.get("DataSources", []):
                data_sources.append(
                    RsDataSource(
                        id=ds_data.get("Id"),
                        name=ds_data.get("Name"),
                        data_source_type=ds_data.get("DataSourceType"),
                        connection_string=ds_data.get("ConnectionString"),
                        enabled=ds_data.get("Enabled", True),
                        path=ds_data.get("Path"),
                        description=ds_data.get("Description"),
                        credential_retrieval=ds_data.get("CredentialRetrieval"),
                        data_source_sub_type=ds_data.get("DataSourceSubType"),
                        credentials_by_user=ds_data.get("CredentialsByUser"),
                        credentials_in_server=ds_data.get("CredentialsInServer"),
                        data_model_data_source=ds_data.get("DataModelDataSource"),
                    )
                )

            return data_sources

        except requests.RequestException as e:
            logger.error(f"Failed to get data sources for {item_path}: {str(e)}")
            raise

    def test_item_data_source_connection(
        self, item_path: str, data_source_name: str = None
    ) -> Dict[str, bool]:
        """
        Test data source connections for a catalog item

        Args:
            item_path: Path to the catalog item
            data_source_name: Specific data source name to test (optional)

        Returns:
            Dictionary with data source names as keys and test results as values
        """
        try:
            rsitem = self.client.get_catalog_item(item_path)
            data_sources = self.get_item_data_sources(item_path)

            if not data_sources:
                logger.warning(f"No data sources found for item: {item_path}")
                return {}

            # Filter by specific data source name if provided
            if data_source_name:
                data_sources = [
                    ds for ds in data_sources if ds.name == data_source_name
                ]
                if not data_sources:
                    logger.warning(
                        f"Data source '{data_source_name}' not found in item: {item_path}"
                    )
                    return {}

            results = {}

            for ds in data_sources:
                try:
                    # Test connection by attempting to get data source details
                    formatted_path = self.client._get_catalog_item_path(item_path)

                    payload = {"DataSourceName": ds.id}

                    endpoint = f"{RsItemType(rsitem.item_type).value}s({rsitem.id})/Model.CheckDataSourceConnection"

                    response = self.client._make_request("POST", endpoint, json=payload)
                    data = response.json()

                    # If we can retrieve the data source details, consider it a successful test
                    # Note: SSRS REST API doesn't have a direct "test connection" endpoint
                    # This is a basic connectivity test
                    results[ds.id] = response.status_code == 200 and data.get(
                        "IsSuccessful", False
                    )

                    logger.info(
                        f"Data source '{ds.connection_string}' ({ds.id}) test result: {results[ds.id]}"
                    )

                except requests.RequestException as e:
                    logger.error(f"Failed to test data source '{ds.id}': {str(e)}")
                    results[ds.id] = False

            return results

        except Exception as e:
            logger.error(f"Failed to test data sources for {item_path}: {str(e)}")
            raise

    def test_data_source_connection(
        self, item_path: str, data_source: RsDataSource = None
    ) -> bool:
        """
        Test connection for a data source

        Args:
            item_path: Path to the catalog item
            data_source: Specific data source name to test (optional)

        Returns:
            Boolean with result
        """
        try:
            rsitem = self.client.get_catalog_item(item_path)
            result = {}

            if not data_source:
                logger.warning(f"No data source")
                return False

            try:
                # Test connection by attempting to get data source details
                if RsItemType(rsitem.item_type).value == "Report":
                    payload = {"DataSourceName": data_source.name}
                else:
                    payload = {"DataSourceName": data_source.id}

                endpoint = f"{RsItemType(rsitem.item_type).value}s({rsitem.id})/Model.CheckDataSourceConnection"

                response = self.client._make_request("POST", endpoint, json=payload)
                data = response.json()

                # If we can retrieve the data source details, consider it a successful test
                # Note: SSRS REST API doesn't have a direct "test connection" endpoint
                # This is a basic connectivity test
                result = {
                    "status": response.status_code == 200
                    and data.get("IsSuccessful", False),
                    "error": data.get("ErrorMessage", None),
                }

                logger.info(
                    f"Data source '{data_source.connection_string}' ({data_source.id}) test result: {result['status']}"
                )

            except requests.RequestException as e:
                logger.error(f"Failed to test data source '{data_source.id}': {str(e)}")
                result = {"status": False, "error": None}

            return result

        except Exception as e:
            logger.error(
                f"Failed to test data source '{data_source.id}' for {item_path}: {str(e)}"
            )
            raise

    def set_item_data_source(
        self, item_path: str, data_sources: List[RsDataSource]
    ) -> bool:
        """
        Set/update data sources for a catalog item

        Args:
            item_path: Path to the catalog item
            data_sources: List of RsDataSource objects to set

        Returns:
            True if successful, False otherwise
        """
        formatted_path = self.client._get_catalog_item_path(item_path)
        endpoint = f"CatalogItems(Path='{formatted_path}')/DataSources"

        try:
            # Convert data sources to API format
            ds_payload = []
            for ds in data_sources:
                ds_dict = {
                    "Name": ds.name,
                    "DataSourceType": ds.data_source_type,
                    "ConnectionString": ds.connection_string,
                    "Enabled": ds.enabled,
                    "IsConnectionStringOverridden": True,
                }

                if ds.description:
                    ds_dict["Description"] = ds.description

                if ds.credentials:
                    if isinstance(ds.credentials, CredentialsByUser):
                        ds_dict["CredentialRetrieval"] = "Prompt"
                        ds_dict["UserName"] = ds.credentials.username
                        if ds.credentials.domain:
                            ds_dict["UserName"] = (
                                f"{ds.credentials.domain}\\{ds.credentials.username}"
                            )
                    elif isinstance(ds.credentials, CredentialsInServer):
                        ds_dict["CredentialRetrieval"] = "Store"
                        ds_dict["UserName"] = ds.credentials.username
                        ds_dict["Password"] = ds.credentials.password
                        ds_dict["WindowsCredentials"] = (
                            ds.credentials.windows_credentials
                        )
                        if ds.credentials.domain:
                            ds_dict["UserName"] = (
                                f"{ds.credentials.domain}\\{ds.credentials.username}"
                            )
                    elif isinstance(ds.credentials, NoCredentials):
                        ds_dict["CredentialRetrieval"] = "None"

                ds_payload.append(ds_dict)

            # Update data sources
            response = self.client._make_request(
                "PUT", endpoint, json={"value": ds_payload}
            )

            success = response.status_code in [200, 204]
            logger.info(
                f"Set data sources for {item_path}: {'Success' if success else 'Failed'}"
            )

            return success

        except requests.RequestException as e:
            logger.error(f"Failed to set data sources for {item_path}: {str(e)}")
            return False
