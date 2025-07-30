#!/usr/bin/env python3
"""
Unit tests for SSRS Python Library
"""

import unittest
from unittest.mock import Mock, patch
from ssrs_library import (
    SSRSRestClient,
    SSRSDataSourceManager,
    RsDataSource,
    RsItem,
    RsItemType,
    CredentialsByUser,
    CredentialsInServer,
    NoCredentials,
    create_credentials_by_user,
    create_credentials_in_server,
    create_no_credentials,
)

from dotenv import load_dotenv
import os

load_dotenv()

server_url = os.getenv("SSRS_SERVER_URL", "http://your-ssrs-server/reports")
username = os.getenv("SSRS_USERNAME", "your-username")
password = os.getenv("SSRS_PASSWORD", "your-password")
domain = os.getenv("SSRS_DOMAIN", "your-domain")


class TestSSRSRestClient(unittest.TestCase):
    """Test cases for SSRSRestClient"""

    def setUp(self):
        """Set up test fixtures"""

        self.client = SSRSRestClient(
            server_url=server_url, username=username, password=password, domain=domain
        )

    def test_client_initialization(self):
        """Test client initialization"""
        self.assertEqual(self.client.server_url, server_url)
        self.assertEqual(self.client.api_base, f"{server_url}/api/v2.0")
        self.assertIsNotNone(self.client.auth)
        self.assertIsNotNone(self.client.session)

    def test_client_initialization_without_auth(self):
        """Test client initialization without authentication"""
        client = SSRSRestClient(server_url=server_url)
        self.assertIsNone(client.auth)

    def test_get_catalog_item_path_formatting(self):
        """Test catalog item path formatting"""
        # Test path without leading slash
        formatted = self.client._get_catalog_item_path("MyReport")
        self.assertEqual(formatted, "/MyReport")

        # Test path with leading slash
        formatted = self.client._get_catalog_item_path("/MyReport")
        self.assertEqual(formatted, "/MyReport")

        # Test path with special characters
        formatted = self.client._get_catalog_item_path("/My Report & Data")
        self.assertEqual(formatted, "/My%20Report%20%26%20Data")

    @patch("ssrs_library.requests.Session.request")
    def test_make_request_success(self, mock_request):
        """Test successful API request"""
        # Mock successful response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"test": "data"}
        mock_response.raise_for_status.return_value = None
        mock_request.return_value = mock_response

        response = self.client._make_request("GET", "test-endpoint")

        self.assertEqual(response.status_code, 200)
        mock_request.assert_called_once()

    @patch("ssrs_library.requests.Session.request")
    def test_make_request_failure(self, mock_request):
        """Test failed API request"""
        # Mock failed response
        mock_request.side_effect = Exception("Request failed")

        with self.assertRaises(Exception):
            self.client._make_request("GET", "test-endpoint")

    @patch("ssrs_library.requests.Session.request")
    def test_test_connection_success(self, mock_request):
        """Test successful connection test"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.raise_for_status.return_value = None
        mock_request.return_value = mock_response

        result = self.client.test_connection()
        self.assertTrue(result)

    @patch("ssrs_library.requests.Session.request")
    def test_test_connection_failure(self, mock_request):
        """Test failed connection test"""
        import requests

        mock_request.side_effect = requests.RequestException("Connection failed")
        result = self.client.test_connection()
        self.assertFalse(result)

    @patch("ssrs_library.requests.Session.request")
    def test_get_catalog_item(self, mock_request):
        """Test getting catalog item"""
        # Mock response data
        mock_data = {
            "Name": "TestReport",
            "Path": "/TestReport",
            "Type": "Report",
            "Id": "test-id",
            "Description": "Test description",
            "Hidden": False,
            "Size": 1024,
            "CreationDate": "2023-01-01T00:00:00Z",
            "ModificationDate": "2023-01-02T00:00:00Z",
            "CreatedBy": "testuser",
            "ModifiedBy": "testuser",
        }

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = mock_data
        mock_response.raise_for_status.return_value = None
        mock_request.return_value = mock_response

        item = self.client.get_catalog_item("/TestReport")

        self.assertEqual(item.name, "TestReport")
        self.assertEqual(item.path, "/TestReport")
        self.assertEqual(item.item_type, RsItemType.REPORT)
        self.assertEqual(item.id, "test-id")
        self.assertEqual(item.description, "Test description")
        self.assertFalse(item.hidden)

    @patch("ssrs_library.requests.Session.request")
    def test_get_catalog_items(self, mock_request):
        """Test getting catalog items"""
        # Mock response data
        mock_data = {
            "value": [
                {
                    "Name": "Report1",
                    "Path": "/Report1",
                    "Type": "Report",
                    "Id": "report1-id",
                },
                {
                    "Name": "Folder1",
                    "Path": "/Folder1",
                    "Type": "Folder",
                    "Id": "folder1-id",
                },
            ]
        }

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = mock_data
        mock_response.raise_for_status.return_value = None
        mock_request.return_value = mock_response

        items = self.client.get_catalog_items("/")

        self.assertEqual(len(items), 2)
        self.assertEqual(items[0].name, "Report1")
        self.assertEqual(items[0].item_type, RsItemType.REPORT)
        self.assertEqual(items[1].name, "Folder1")
        self.assertEqual(items[1].item_type, RsItemType.FOLDER)


class TestSSRSDataSourceManager(unittest.TestCase):
    """Test cases for SSRSDataSourceManager"""

    def setUp(self):
        """Set up test fixtures"""
        self.mock_client = Mock(spec=SSRSRestClient)
        self.ds_manager = SSRSDataSourceManager(self.mock_client)

    def test_manager_initialization(self):
        """Test data source manager initialization"""
        self.assertEqual(self.ds_manager.client, self.mock_client)

    def test_get_item_data_sources(self):
        """Test getting item data sources"""
        # Mock response data
        mock_data = {
            "DataSources": [
                {
                    "Name": "DataSource1",
                    "DataSourceType": "SQL",
                    "ConnectionString": "Server=test;Database=db1;",
                    "Enabled": True,
                    "Path": "/DataSources/DataSource1",
                    "Id": "ds1-id",
                    "Description": "Test data source",
                }
            ]
        }
        mock_response = Mock()
        mock_response.json.return_value = mock_data
        self.mock_client._make_request.return_value = mock_response
        self.mock_client._get_catalog_item_path.return_value = "/TestReport"
        data_sources = self.ds_manager.get_item_data_sources("/TestReport")
        self.assertEqual(len(data_sources), 1)
        self.assertEqual(data_sources[0].name, "DataSource1")
        self.assertEqual(data_sources[0].data_source_type, "SQL")
        self.assertEqual(data_sources[0].connection_string, "Server=test;Database=db1;")
        self.assertTrue(data_sources[0].enabled)

    def test_test_item_data_source_connection(self):
        """Test testing item data source connections"""
        # Mock get_item_data_sources
        mock_ds = RsDataSource(
            name="TestDS",
            id="00000000-0000-0000-0000-000000000000",
            data_source_type="SQL",
            connection_string="Server=test;",
        )
        # Patch get_catalog_item to return a mock with a real RsItemType
        mock_item = Mock()
        mock_item.item_type = RsItemType.REPORT
        mock_item.id = "item-id"
        with patch.object(
            self.ds_manager, "get_item_data_sources", return_value=[mock_ds]
        ), patch.object(self.mock_client, "get_catalog_item", return_value=mock_item):
            # Mock successful connection test
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"IsSuccessful": True}
            self.mock_client._make_request.return_value = mock_response
            self.mock_client._get_catalog_item_path.return_value = "/TestReport"
            results = self.ds_manager.test_item_data_source_connection("/TestReport")
            self.assertEqual(len(results), 1)
            self.assertIn("00000000-0000-0000-0000-000000000000", results)
            self.assertTrue(results["00000000-0000-0000-0000-000000000000"])

    def test_test_item_data_source_connection_specific_ds(self):
        """Test testing specific data source connection"""
        # Mock multiple data sources
        mock_ds1 = RsDataSource(
            name="DS1",
            id="00000000-0000-0000-0000-000000000000",
            data_source_type="SQL",
            connection_string="Server=test1;",
        )
        mock_ds2 = RsDataSource(
            name="DS2",
            id="00000000-0000-0000-0000-000000000001",
            data_source_type="SQL",
            connection_string="Server=test2;",
        )
        mock_item = Mock()
        mock_item.item_type = RsItemType.REPORT
        mock_item.id = "item-id"
        with patch.object(
            self.ds_manager, "get_item_data_sources", return_value=[mock_ds1, mock_ds2]
        ), patch.object(self.mock_client, "get_catalog_item", return_value=mock_item):
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"IsSuccessful": True}
            self.mock_client._make_request.return_value = mock_response
            self.mock_client._get_catalog_item_path.return_value = "/TestReport"
            # Test specific data source
            results = self.ds_manager.test_item_data_source_connection(
                "/TestReport", "DS2"
            )
            self.assertEqual(len(results), 1)
            self.assertIn("00000000-0000-0000-0000-000000000001", results)
            self.assertNotIn("00000000-0000-0000-0000-000000000000", results)

    def test_set_item_data_source(self):
        """Test setting item data sources"""
        # Create test data source
        credentials = create_credentials_in_server("user", "pass", "domain")
        data_source = RsDataSource(
            name="TestDS",
            data_source_type="SQL",
            connection_string="Server=test;Database=db;",
            credentials=credentials,
            enabled=True,
            description="Test DS",
        )

        # Mock successful response
        mock_response = Mock()
        mock_response.status_code = 200
        self.mock_client._make_request.return_value = mock_response
        self.mock_client._get_catalog_item_path.return_value = "/TestReport"

        result = self.ds_manager.set_item_data_source("/TestReport", [data_source])

        self.assertTrue(result)
        self.mock_client._make_request.assert_called_once()


class TestCredentials(unittest.TestCase):
    """Test cases for credential classes"""

    def test_credentials_by_user(self):
        """Test CredentialsByUser creation"""
        creds = create_credentials_by_user("user", "pass", "domain")

        self.assertIsInstance(creds, CredentialsByUser)
        self.assertEqual(creds.username, "user")
        self.assertEqual(creds.password, "pass")
        self.assertEqual(creds.domain, "domain")

    def test_credentials_in_server(self):
        """Test CredentialsInServer creation"""
        creds = create_credentials_in_server("user", "pass", "domain", False)

        self.assertIsInstance(creds, CredentialsInServer)
        self.assertEqual(creds.username, "user")
        self.assertEqual(creds.password, "pass")
        self.assertEqual(creds.domain, "domain")
        self.assertFalse(creds.windows_credentials)

    def test_no_credentials(self):
        """Test NoCredentials creation"""
        creds = create_no_credentials()

        self.assertIsInstance(creds, NoCredentials)


class TestDataStructures(unittest.TestCase):
    """Test cases for data structures"""

    def test_rs_data_source(self):
        """Test RsDataSource creation"""
        ds = RsDataSource(
            name="TestDS",
            data_source_type="SQL",
            connection_string="Server=test;",
            enabled=False,
            description="Test",
        )

        self.assertEqual(ds.name, "TestDS")
        self.assertEqual(ds.data_source_type, "SQL")
        self.assertEqual(ds.connection_string, "Server=test;")
        self.assertFalse(ds.enabled)
        self.assertEqual(ds.description, "Test")

    def test_rs_item(self):
        """Test RsItem creation"""
        item = RsItem(
            name="TestReport",
            path="/TestReport",
            item_type=RsItemType.REPORT,
            description="Test report",
            hidden=True,
        )

        self.assertEqual(item.name, "TestReport")
        self.assertEqual(item.path, "/TestReport")
        self.assertEqual(item.item_type, RsItemType.REPORT)
        self.assertEqual(item.description, "Test report")
        self.assertTrue(item.hidden)


class TestIntegration(unittest.TestCase):
    """Integration test cases"""

    @patch("ssrs_library.requests.Session")
    def test_full_workflow(self, mock_session_class):
        """Test full workflow integration"""
        # Mock session and responses
        mock_session = Mock()
        mock_session_class.return_value = mock_session
        # Mock connection test
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.raise_for_status.return_value = None
        mock_session.request.return_value = mock_response
        # Initialize client
        client = SSRSRestClient(
            server_url=server_url, username=username, password=password
        )
        # Test connection
        self.assertTrue(client.test_connection())
        # Initialize data source manager
        ds_manager = SSRSDataSourceManager(client)
        # Mock data source response
        mock_ds_data = {
            "DataSources": [
                {
                    "Name": "TestDS",
                    "DataSourceType": "SQL",
                    "ConnectionString": "Server=test;",
                    "Enabled": True,
                }
            ]
        }
        mock_response.json.return_value = mock_ds_data
        # Get data sources
        data_sources = ds_manager.get_item_data_sources("/TestReport")
        self.assertEqual(len(data_sources), 1)
        self.assertEqual(data_sources[0].name, "TestDS")


if __name__ == "__main__":
    # Create test suite
    test_suite = unittest.TestSuite()

    # Add test cases
    test_classes = [
        TestSSRSRestClient,
        TestSSRSDataSourceManager,
        TestCredentials,
        TestDataStructures,
        TestIntegration,
    ]

    for test_class in test_classes:
        tests = unittest.TestLoader().loadTestsFromTestCase(test_class)
        test_suite.addTests(tests)

    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(test_suite)

    # Exit with appropriate code
    exit(0 if result.wasSuccessful() else 1)
