"""
Advanced usage examples for SSRS Python Tools
"""

import os
import urllib3
from ssrs_library import (
    SSRSRestClient, 
    SSRSDataSourceManager,
    create_credentials_in_server,
    create_credentials_by_user,
    RsDataSource
)
from dotenv import load_dotenv

load_dotenv()

urllib3.disable_warnings()

def example_basic_usage():
    """Basic usage example"""
    
    server_url = os.getenv('SSRS_SERVER_URL')
    username = os.getenv('SSRS_USERNAME')
    password = os.getenv('SSRS_PASSWORD')
    domain = os.getenv('SSRS_DOMAIN')
    
    if not all([server_url, username, password]):
        raise ValueError("Missing required environment variables")
    
    client = SSRSRestClient(
        server_url=server_url,
        username=username,
        password=password,
        domain=domain,
        verify_ssl=False
    )    

    # Test connection
    if client.test_connection():
        print("✓ Connected to SSRS server")
    else:
        print("✗ Failed to connect")
        return
    
    # Get catalog items
    items = client.get_catalog_items('/Demo/Manage_Delivery/P1')
    print(f"Found {len(items)} items in /Demo/Manage_Delivery/P1 folder")
    
    # Test data sources for a specific report
    ds_manager = SSRSDataSourceManager(client)
    results = ds_manager.test_item_data_source_connection('/Demo/Manage_Delivery/P1/TestDashboard')
    
    for ds_name, success in results.items():
        status = "✓" if success else "✗"
        print(f"{status} Data source '{ds_name}': {'OK' if success else 'FAILED'}")


def example_gitlab_ci_usage():
    """Example for GitLab CI environment"""
    
    # Get configuration from environment variables
    server_url = os.getenv('SSRS_SERVER_URL')
    username = os.getenv('SSRS_USERNAME')
    password = os.getenv('SSRS_PASSWORD')
    domain = os.getenv('SSRS_DOMAIN')
    
    if not all([server_url, username, password]):
        raise ValueError("Missing required environment variables")
    
    client = SSRSRestClient(
        server_url=server_url,
        username=username,
        password=password,
        domain=domain,
        verify_ssl=False
    )
    
    # Test multiple reports
    reports_to_test = [
        '/Demo/Manage_Delivery/P1/TestDashboard',
        '/Demo/Manage_Delivery/P1/TestDashboard3',
        '/Demo/Manage_Delivery/P1/Dashboard_RDL'
    ]
    
    ds_manager = SSRSDataSourceManager(client)
    all_passed = True
    
    for report_path in reports_to_test:
        print(f"\n🔍 Testing report: {report_path}")
        
        try:
            data_sources = ds_manager.get_item_data_sources(report_path)
            for data_source in data_sources:
                result = ds_manager.test_data_source_connection(report_path, data_source)
                if result['status']:
                    print(f"✅ Data source '{data_source.connection_string}': OK")
                else:
                    print(f"❌ Data source '{data_source.connection_string}': FAILED")
                    print(f"{result['error']}")
                    all_passed = False

            # results = ds_manager.test_item_data_source_connection(report_path)
            
            # if not results:
            #     print(f"⚠️  No data sources found for {report_path}")
            #     continue
            
            # for ds_name, success in results.items():
            #     if success:
            #         print(f"✅ Data source '{ds_name}': OK")
            #     else:
            #         print(f"❌ Data source '{ds_name}': FAILED")
            #         all_passed = False
                    
        except Exception as e:
            print(f"❌ Error testing {report_path}: {str(e)}")
            all_passed = False
    
    if not all_passed:
        print("\n💥 Some data source tests failed!")
        exit(1)
    else:
        print("\n🎉 All data source tests passed!")


def example_update_data_sources():
    """Example of updating data sources"""
    
    client = SSRSRestClient(
        server_url='http://your-server/reports',
        username='your-username',
        password='your-password'
    )
    
    ds_manager = SSRSDataSourceManager(client)
    
    # Create new data source configuration
    new_data_source = RsDataSource(
        name='MyDatabase',
        data_source_type='SQL',
        connection_string='Server=newserver;Database=mydb;',
        credentials=create_credentials_in_server(
            username='db_user',
            password='db_password',
            windows_credentials=False
        ),
        enabled=True,
        description='Updated database connection'
    )
    
    # Update data source for a report
    success = ds_manager.set_item_data_source(
        item_path='/Reports/SalesReport',
        data_sources=[new_data_source]
    )
    
    if success:
        print("✅ Data source updated successfully")
    else:
        print("❌ Failed to update data source")


def example_batch_testing():
    """Example of batch testing multiple items"""
    
    client = SSRSRestClient(
        server_url='http://your-server/reports',
        username='your-username',
        password='your-password'
    )
    
    ds_manager = SSRSDataSourceManager(client)
    
    # Get all reports in a folder
    items = client.get_catalog_items('/Reports/Sales')
    reports = [item for item in items if item.item_type.value == 'Report']
    
    print(f"Found {len(reports)} reports to test")
    
    failed_reports = []
    
    for report in reports:
        print(f"\n📊 Testing report: {report.name}")
        
        try:
            results = ds_manager.test_item_data_source_connection(report.path)
            
            if not results:
                print("   ⚠️  No data sources")
                continue
            
            report_failed = False
            for ds_name, success in results.items():
                if success:
                    print(f"   ✅ {ds_name}: OK")
                else:
                    print(f"   ❌ {ds_name}: FAILED")
                    report_failed = True
            
            if report_failed:
                failed_reports.append(report.name)
                
        except Exception as e:
            print(f"   💥 Error: {str(e)}")
            failed_reports.append(report.name)
    
    # Summary
    print(f"\n📈 Summary:")
    print(f"   Total reports tested: {len(reports)}")
    print(f"   Failed reports: {len(failed_reports)}")
    
    if failed_reports:
        print("   Failed report list:")
        for report_name in failed_reports:
            print(f"     - {report_name}")


def example_custom_logging():
    """Example with custom logging configuration"""
    
    import logging
    
    # Configure custom logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('ssrs_test.log'),
            logging.StreamHandler()
        ]
    )
    
    logger = logging.getLogger('ssrs_test')
    
    client = SSRSRestClient(
        server_url='http://your-server/reports',
        username='your-username',
        password='your-password'
    )
    
    logger.info("Starting SSRS data source tests")
    
    ds_manager = SSRSDataSourceManager(client)
    
    try:
        results = ds_manager.test_item_data_source_connection('/Reports/MyReport')
        
        for ds_name, success in results.items():
            if success:
                logger.info(f"Data source test passed: {ds_name}")
            else:
                logger.error(f"Data source test failed: {ds_name}")
                
    except Exception as e:
        logger.exception(f"Test execution failed: {str(e)}")
        raise
    
    logger.info("SSRS data source tests completed")


if __name__ == "__main__":
    # Run examples
    print("🚀 Running SSRS Python Tools examples\n")
    
    try:
        # print("1️⃣  Basic Usage Example")
        # example_basic_usage()
        # print("\n" + "="*50 + "\n")
        
        # print("2️⃣  GitLab CI Usage Example")
        example_gitlab_ci_usage()
        # print("\n" + "="*50 + "\n")
        
        # print("3️⃣  Batch Testing Example")
        # example_batch_testing()
        # print("\n" + "="*50 + "\n")
        
    except Exception as e:
        print(f"❌ Example execution failed: {str(e)}")
        import traceback
        traceback.print_exc()