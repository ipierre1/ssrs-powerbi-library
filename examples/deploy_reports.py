"""
Example script for deploying SSRS reports
"""

import os
import json
from pathlib import Path
from ssrs_library import SSRSRestClient, SSRSDataSourceManager, RsDataSource
from typing import Dict, List

class SSRSDeploymentManager:
    """Manager for SSRS report deployments"""
    
    def __init__(self, client: SSRSRestClient):
        self.client = client
        self.ds_manager = SSRSDataSourceManager(client)
    
    def deploy_reports_from_config(self, config_file: str) -> bool:
        """
        Deploy reports based on configuration file
        
        Args:
            config_file: Path to deployment configuration JSON file
            
        Returns:
            True if all deployments successful
        """
        
        with open(config_file, 'r') as f:
            config = json.load(f)
        
        success = True
        
        for deployment in config.get('deployments', []):
            report_path = deployment['report_path']
            data_sources = deployment.get('data_sources', [])
            
            print(f"📦 Deploying: {report_path}")
            
            # Update data sources if specified
            if data_sources:
                ds_objects = []
                for ds_config in data_sources:
                    ds = RsDataSource(
                        name=ds_config['name'],
                        data_source_type=ds_config['type'],
                        connection_string=ds_config['connection_string'],
                        enabled=ds_config.get('enabled', True)
                    )
                    ds_objects.append(ds)
                
                if not self.ds_manager.set_item_data_source(report_path, ds_objects):
                    print(f"❌ Failed to update data sources for {report_path}")
                    success = False
                    continue
            
            # Test data sources after deployment
            results = self.ds_manager.test_item_data_source_connection(report_path)
            
            all_ds_ok = all(results.values()) if results else True
            
            if all_ds_ok:
                print(f"✅ Successfully deployed: {report_path}")
            else:
                print(f"⚠️  Deployed with data source issues: {report_path}")
                success = False
        
        return success


def main():
    """Main deployment function"""
    
    # Get configuration from environment
    server_url = os.getenv('SSRS_SERVER_URL')
    username = os.getenv('SSRS_USERNAME') 
    password = os.getenv('SSRS_PASSWORD')
    domain = os.getenv('SSRS_DOMAIN')
    
    config_file = os.getenv('SSRS_DEPLOY_CONFIG', 'deployment_config.json')
    
    if not all([server_url, username, password]):
        print("❌ Missing required environment variables")
        exit(1)
    
    if not Path(config_file).exists():
        print(f"❌ Configuration file not found: {config_file}")
        exit(1)
    
    # Initialize client
    client = SSRSRestClient(
        server_url=server_url,
        username=username,
        password=password,
        domain=domain
    )
    
    if not client.test_connection():
        print("❌ Failed to connect to SSRS server")
        exit(1)
    
    print("✅ Connected to SSRS server")
    
    # Deploy reports
    deploy_manager = SSRSDeploymentManager(client)
    
    if deploy_manager.deploy_reports_from_config(config_file):
        print("🎉 All deployments completed successfully")
    else:
        print("💥 Some deployments failed")
        exit(1)


if __name__ == "__main__":
    main()