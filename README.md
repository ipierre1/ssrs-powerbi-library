# SSRS Python Tools

A modern Python library to replace the PowerShell ReportingServicesTools module, designed for automation and CI/CD pipelines (e.g., GitLab CI/CD).

**Repository:** [ipierre1/ssrs-powerbi-library](https://github.com/ipierre1/ssrs-powerbi-library)  
**PyPI package:** `ssrs-powerbi-library`

---

## 🚀 Features

- **Full replacement** for PowerShell ReportingServicesTools
- **Native REST API** for SQL Server Reporting Services (SSRS)
- **NTLM authentication** support (Windows credentials)
- **CI/CD integration** (GitLab, GitHub, Azure, etc.)
- **Data source connection testing**
- **Report and catalog item management**
- **Flexible configuration** via environment variables
- **Advanced logging** for debugging and monitoring

---

## 📦 Installation

```bash
# Install from PyPI (recommended)
pip install ssrs-powerbi-library

# Or install from source
git clone https://github.com/ipierre1/ssrs-powerbi-library.git
cd ssrs-powerbi-library
pip install -r requirements.txt
pip install -e .
```

### Requirements

- Python 3.7+
- Access to an SSRS server with REST API enabled
- Credentials for NTLM authentication

---

## 📚 End-User API

### Main Classes & Functions

| Name                                             | Type     | Description                                               |
| ------------------------------------------------ | -------- | --------------------------------------------------------- |
| `SSRSRestClient`                                 | Class    | Main client for SSRS REST API                             |
| &nbsp;&nbsp;• `get_catalog_item`                 | Method   | Get info for a catalog item                               |
| &nbsp;&nbsp;• `get_catalog_items`                | Method   | List catalog items in a folder                            |
| &nbsp;&nbsp;• `test_connection`                  | Method   | Test connection to SSRS server                            |
| `SSRSDataSourceManager`                          | Class    | Data source management (test, set, list, etc.)            |
| &nbsp;&nbsp;• `get_item_data_sources`            | Method   | List data sources for a catalog item                      |
| &nbsp;&nbsp;• `test_item_data_source_connection` | Method   | Test all or one data source connection for a catalog item |
| &nbsp;&nbsp;• `test_data_source_connection`      | Method   | Test a specific data source connection                    |
| &nbsp;&nbsp;• `set_item_data_source`             | Method   | Set/update data sources for a catalog item                |
| `SSRSSecurityManager`                            | Class    | Security/permissions management                           |
| &nbsp;&nbsp;• `get_item_permissions`             | Method   | Get permissions for a catalog item                        |
| &nbsp;&nbsp;• `set_item_permissions`             | Method   | Set permissions for a catalog item                        |
| &nbsp;&nbsp;• `get_roles`                        | Method   | List available roles                                      |
| &nbsp;&nbsp;• `add_group_or_user`                | Method   | Add a group or user to an item                            |
| &nbsp;&nbsp;• `remove_group_or_user`             | Method   | Remove a group or user from an item                       |
| &nbsp;&nbsp;• `list_users_and_groups`            | Method   | List users and groups with access                         |
| `create_credentials_by_user`                     | Function | Helper to create `CredentialsByUser`                      |
| `create_credentials_in_server`                   | Function | Helper to create `CredentialsInServer`                    |
| `create_no_credentials`                          | Function | Helper to create `NoCredentials`                          |

### Types, Enums & Dataclasses

| Name                  | Type      | Description                                      |
| --------------------- | --------- | ------------------------------------------------ |
| `RsItem`              | Dataclass | Represents a catalog item (report, folder, etc.) |
| `RsDataSource`        | Dataclass | Represents a data source                         |
| `RsItemType`          | Enum      | Catalog item types (Report, Folder, etc.)        |
| `DataSourceType`      | Enum      | Data source types (SQL, OLEDB, etc.)             |
| `RsCredentials`       | Dataclass | Base class for credentials                       |
| `CredentialsByUser`   | Dataclass | User/password credentials                        |
| `CredentialsInServer` | Dataclass | Credentials stored in server                     |
| `NoCredentials`       | Dataclass | No credentials                                   |

---

## 🔧 Configuration

### Environment Variables (for CI/CD)

Set these variables in your CI/CD environment:

```bash
SSRS_SERVER_URL=http://your-ssrs-server/reports
SSRS_USERNAME=your-username
SSRS_PASSWORD=your-password
SSRS_DOMAIN=your-domain  # Optional
```

### Python Usage Example

```python
from ssrs_library.ssrs_library import SSRSRestClient

client = SSRSRestClient(
    server_url='http://your-server/reports',
    username='your-username',
    password='your-password',
    domain='your-domain'  # optional
)

# Example: List catalog items in root folder
items = client.get_catalog_items('/')
for item in items:
    print(item.name, item.item_type)
```

---

## 🧪 Testing

```bash
pytest tests/
```

---

## 📄 License

MIT License
