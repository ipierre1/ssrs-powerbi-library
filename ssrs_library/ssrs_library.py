"""
SSRS Python Library - A Python replacement for ReportingServicesTools PowerShell module
"""

import requests
from requests_ntlm import HttpNtlmAuth
from urllib.parse import urljoin, quote
import json
import logging
from typing import Dict, List, Optional, Union, Any

# Import types
from .types.rsitemtype import RsItemType
from .types.datasourcetype import DataSourceType
from .types.rscredentials import RsCredentials, CredentialsByUser, CredentialsInServer, NoCredentials
from .types.rsdatasource import RsDataSource
from .types.rsitem import RsItem

# Import datasource logic
from .datasource_manager import SSRSDataSourceManager

# Configure logging
logging.basicConfig(level=logging.WARNING)
logger = logging.getLogger(__name__)


class SSRSRestClient:
    """
    SSRS REST API Client - Main class for interacting with SSRS REST endpoints
    """
    
    def __init__(self, 
                 server_url: str, 
                 username: str = None, 
                 password: str = None,
                 domain: str = None,
                 verify_ssl: bool = True,
                 timeout: int = 3600):
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
        self.server_url = server_url.rstrip('/')
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
        self.session.headers.update({
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        })
    
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
        url = urljoin(self.api_base + '/', endpoint.lstrip('/'))
        
        try:
            response = self.session.request(
                method=method,
                url=url,
                timeout=self.timeout,
                verify=self.verify_ssl,
                **kwargs
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
        if not path.startswith('/'):
            path = '/' + path
        return quote(path, safe='/')
    
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
        
        response = self._make_request('GET', endpoint)
        data = response.json()
        
        return RsItem(
            name=data.get('Name'),
            path=data.get('Path'),
            item_type=RsItemType(data.get('Type')),
            id=data.get('Id'),
            description=data.get('Description'),
            hidden=data.get('Hidden', False),
            size=data.get('Size'),
            created_date=data.get('CreationDate'),
            modified_date=data.get('ModificationDate'),
            created_by=data.get('CreatedBy'),
            modified_by=data.get('ModifiedBy')
        )
    
    def get_catalog_items(self, folder_path: str = '/') -> List[RsItem]:
        """
        Get catalog items in a folder
        
        Args:
            folder_path: Path to the folder (default: root '/')
            
        Returns:
            List of RsItem objects
        """
        formatted_path = self._get_catalog_item_path(folder_path)
        endpoint = f"Folders(Path='{formatted_path}')/CatalogItems?`$expand=Properties"
        
        response = self._make_request('GET', endpoint)
        data = response.json()
        
        items = []
        for item_data in data.get('value', []):
            items.append(RsItem(
                name=item_data.get('Name'),
                path=item_data.get('Path'),
                item_type=RsItemType(item_data.get('Type')),
                id=item_data.get('Id'),
                description=item_data.get('Description'),
                hidden=item_data.get('Hidden', False),
                size=item_data.get('Size'),
                created_date=item_data.get('CreationDate'),
                modified_date=item_data.get('ModificationDate'),
                created_by=item_data.get('CreatedBy'),
                modified_by=item_data.get('ModifiedBy')
            ))
        
        return items
    
    def test_connection(self) -> bool:
        """
        Test connection to SSRS server
        
        Returns:
            True if connection successful, False otherwise
        """
        try:
            response = self._make_request('GET', '')
            return response.status_code == 200
        except requests.RequestException:
            return False
