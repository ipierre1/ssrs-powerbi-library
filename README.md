# ssrs-powerbi-library

A Python library for automating Power BI Report Server (PBIRS) and SQL Server Reporting Services (SSRS) via the REST API v2.0. Designed to replace PowerShell `ReportingServicesTools` in CI/CD pipelines.

**Repository:** [ipierre1/ssrs-powerbi-library](https://github.com/ipierre1/ssrs-powerbi-library)

---

## Features

- **Easy API** — connect once, get resource handle objects, call methods on them
- **NTLM authentication** — native Windows/domain credentials via `requests-ntlm`
- **Power BI reports** — upload, delete, data sources, data model parameters, cache refresh plans, security
- **Paginated (SSRS) reports** — upload, delete, data sources, report parameters, cache refresh plans, security
- **Folder management** — create, list, delete, security policies
- **Schedule helpers** — build daily / weekly / monthly schedules with a fluent API
- **Row-level security** — manage RLS role assignments on Power BI reports
- **Typed exceptions** — `PBIRSNotFound`, `PBIRSConflict`, `PBIRSAuthError`
- **CI/CD ready** — works in GitLab, GitHub Actions, Azure Pipelines, etc.

---

## Installation

```bash
pip install ssrs-powerbi-library
```

Or from source:

```bash
git clone https://github.com/ipierre1/ssrs-powerbi-library.git
cd ssrs-powerbi-library
pip install -e .
```

**Requirements:** Python 3.8+, network access to PBIRS, NTLM-capable credentials.

---

## Quick start

```python
from ssrs_library import PBIRSClient

client = PBIRSClient(
    base_url="http://pbirs.corp.local/reports",
    username="svc_deploy",
    password="secret",
    domain="CORP",
)

client.test_connection()   # raises PBIRSAuthError / PBIRSError on failure

# Upload a .pbix
report = client.upload_powerbi_report(
    folder_path="/Sales",
    file_path="/ci/artifacts/Revenue.pbix",
    name="Revenue",
    overwrite=True,
)
print(report)  # <PowerBIReport name='Revenue' path='/Sales/Revenue'>
```

---

## API reference

### `PBIRSClient`

```python
PBIRSClient(base_url, username, password, domain="", verify_ssl=True, timeout=30)
```

| Method                                                                   | Returns                 | Description                                            |
| ------------------------------------------------------------------------ | ----------------------- | ------------------------------------------------------ |
| `test_connection()`                                                      | `bool`                  | Verify credentials & connectivity                      |
| `get_folder(path)`                                                       | `Folder`                | Fetch a folder by catalog path                         |
| `create_folder(path, description="")`                                    | `Folder`                | Create folder (and intermediate folders)               |
| `list_folders(parent_path=None)`                                         | `List[Folder]`          | List sub-folders                                       |
| `get_powerbi_report(path)`                                               | `PowerBIReport`         | Fetch a .pbix report                                   |
| `list_powerbi_reports(folder_path=None)`                                 | `List[PowerBIReport]`   | List .pbix reports                                     |
| `upload_powerbi_report(folder_path, file_path, name, overwrite=False)`   | `PowerBIReport`         | Upload .pbix (auto-selects multipart for files >25 MB) |
| `get_paginated_report(path)`                                             | `PaginatedReport`       | Fetch a .rdl report                                    |
| `list_paginated_reports(folder_path=None)`                               | `List[PaginatedReport]` | List .rdl reports                                      |
| `upload_paginated_report(folder_path, file_path, name, overwrite=False)` | `PaginatedReport`       | Upload .rdl                                            |

---

### `PowerBIReport`

Obtained from `client.get_powerbi_report(path)` or `client.upload_powerbi_report(...)`.

#### Properties

| Property           | Type   | Description                               |
| ------------------ | ------ | ----------------------------------------- |
| `id`               | `str`  | Catalog GUID                              |
| `name`             | `str`  | Display name                              |
| `path`             | `str`  | Full catalog path                         |
| `description`      | `str`  | Description (empty string if absent)      |
| `has_data_sources` | `bool` | Whether the report has bound data sources |

#### Lifecycle

```python
report.delete()
```

#### Data sources

```python
sources = report.get_datasources()          # List[DataSource]
report.set_datasources([ds1, ds2])          # full replace
```

#### Data model parameters

```python
params = report.get_data_model_parameters()
report.set_data_model_parameters([
    {"Name": "Environment", "Value": "Production"},
    {"Name": "MaxRows",     "Value": "10000"},
])
```

#### Cache refresh plans

```python
plans = report.get_cache_refresh_plans()    # List[CacheRefreshPlan]

plan = report.create_cache_refresh_plan(
    description="Nightly refresh",
    schedule=Schedule.daily(hour=2),
)
```

#### Catalog security (who can view/edit the report)

```python
policies = report.get_policies()
# {"InheritParentSecurity": False, "Policies": [...]}

report.set_policies(policies)               # full overwrite

report.add_user("CORP\\alice", ["Browser"])
report.add_user("CORP\\admins", ["Content Manager"])
report.remove_user("CORP\\alice")
```

Built-in role names: `"Browser"`, `"Content Manager"`, `"Publisher"`, `"Report Builder"`.

#### Row-level security (data model RLS)

```python
roles = report.get_data_model_roles()       # model role definitions
assignments = report.get_data_model_role_assignments()

report.set_data_model_role_assignments([
    {"GroupUserName": "CORP\\alice", "Roles": ["Region_West"]},
    {"GroupUserName": "CORP\\bob",   "Roles": ["Region_East"]},
])

# Convenience helpers (read-modify-write):
report.add_rls_user("CORP\\alice", ["Region_West", "Region_North"])
report.remove_rls_user("CORP\\alice")
```

---

### `PaginatedReport`

Obtained from `client.get_paginated_report(path)` or `client.upload_paginated_report(...)`.

Same properties as `PowerBIReport`. Additional methods:

| Method                                                         | Description                                |
| -------------------------------------------------------------- | ------------------------------------------ |
| `delete()`                                                     | Delete from catalog                        |
| `get_datasources()` / `set_datasources(datasources)`           | Manage data sources                        |
| `get_parameters()` / `set_parameters(params)`                  | Read / update report parameter definitions |
| `get_cache_refresh_plans()`                                    | List cache refresh plans                   |
| `create_cache_refresh_plan(description, schedule, event_type)` | Create a cache refresh plan                |
| `get_policies()` / `set_policies(policy_data)`                 | Read / replace catalog security policies   |
| `add_user(username, roles)`                                    | Grant catalog access (read-modify-write)   |
| `remove_user(username)`                                        | Revoke catalog access (read-modify-write)  |

---

### `Folder`

Obtained from `client.get_folder(path)` or `client.create_folder(path)`.

| Method                                         | Description                            |
| ---------------------------------------------- | -------------------------------------- |
| `list_items()`                                 | Raw catalog items (all types)          |
| `list_powerbi_reports()`                       | `List[PowerBIReport]` in this folder   |
| `list_paginated_reports()`                     | `List[PaginatedReport]` in this folder |
| `list_folders()`                               | Sub-folders                            |
| `delete()`                                     | Delete folder and all contents         |
| `get_policies()` / `set_policies(policy_data)` | Read / replace security policies       |
| `add_user(username, roles)`                    | Grant access (read-modify-write)       |
| `remove_user(username)`                        | Revoke access (read-modify-write)      |

---

### `DataSource`

```python
from ssrs_library import DataSource

# SQL, integrated auth (default)
ds = DataSource("SalesDB", "Server=sql01;Database=Sales;")

# Stored credentials
ds = DataSource(
    name="SalesDB",
    connection_string="Server=sql01;Database=Sales;",
    credential_retrieval="Store",
    username="svc_report",
    password="secret",
    windows_credentials=False,
)

report.set_datasources([ds])
```

| Parameter              | Default  | Description                                |
| ---------------------- | -------- | ------------------------------------------ |
| `name`                 | —        | Data source name                           |
| `connection_string`    | —        | ADO.NET connection string                  |
| `data_source_type`     | `"SQL"`  | Provider type (e.g. `"Oracle"`, `"OLEDB"`) |
| `enabled`              | `True`   | Whether the data source is active          |
| `id`                   | `None`   | GUID (set when reading from server)        |
| `description`          | `None`   | Optional description                       |
| `credential_retrieval` | `"None"` | `"None"`, `"Integrated"`, or `"Store"`     |
| `username`             | `None`   | Username for `"Store"` retrieval           |
| `password`             | `None`   | Password for `"Store"` retrieval           |
| `windows_credentials`  | `True`   | Use Windows auth for stored creds          |

---

### `Schedule`

Helper for building cache-refresh plan schedules.

```python
from ssrs_library import Schedule

# Daily at 02:00 (default)
Schedule.daily()

# Daily at 06:30
Schedule.daily(hour=6, minute=30)

# Every 3 days at 04:00
Schedule.daily(hour=4, interval=3)

# Every Monday and Friday at 08:30
Schedule.weekly(["Monday", "Friday"], hour=8, minute=30)

# Every two weeks on Wednesday
Schedule.weekly(["Wednesday"], interval=2)

# 1st of every month at 03:00 (default)
Schedule.monthly()

# 15th of January and July at 01:00
Schedule.monthly(day=15, months=["January", "July"], hour=1)
```

Pass a `Schedule` instance (or a raw `{"Definition": {...}}` dict) to
`create_cache_refresh_plan()` or `plan.update()`.

---

### `CacheRefreshPlan`

Obtained from `report.get_cache_refresh_plans()` or `report.create_cache_refresh_plan(...)`.

| Method                                    | Description                        |
| ----------------------------------------- | ---------------------------------- |
| `execute()`                               | Trigger an immediate refresh       |
| `update(description=None, schedule=None)` | Modify description and/or schedule |
| `delete()`                                | Delete this plan                   |

```python
plan.update(
    description="Updated nightly refresh",
    schedule=Schedule.daily(hour=3),
)

plan.execute()
plan.delete()
```

---

### Exceptions

```python
from ssrs_library import PBIRSError, PBIRSNotFound, PBIRSConflict, PBIRSAuthError
```

| Exception        | Raised when                    |
| ---------------- | ------------------------------ |
| `PBIRSAuthError` | HTTP 401 or 403                |
| `PBIRSNotFound`  | HTTP 404                       |
| `PBIRSConflict`  | HTTP 409 (item already exists) |
| `PBIRSError`     | Any other HTTP error           |

---

## Configuration patterns

### Direct (script / notebook)

```python
from ssrs_library import PBIRSClient

client = PBIRSClient(
    base_url="http://pbirs.corp.local/reports",
    username="alice",
    password="secret",
    domain="CORP",
)
```

### Environment variables (CI/CD)

```python
import os
from ssrs_library import PBIRSClient

client = PBIRSClient(
    base_url=os.environ["PBIRS_URL"],
    username=os.environ["PBIRS_USER"],
    password=os.environ["PBIRS_PASSWORD"],
    domain=os.environ.get("PBIRS_DOMAIN", ""),
)
```

### `.env` file (local development)

```python
from dotenv import load_dotenv
import os
from ssrs_library import PBIRSClient

load_dotenv()
client = PBIRSClient(
    base_url=os.environ["PBIRS_URL"],
    username=os.environ["PBIRS_USER"],
    password=os.environ["PBIRS_PASSWORD"],
    domain=os.environ.get("PBIRS_DOMAIN", ""),
)
```

---

## CI/CD deploy example

```python
from ssrs_library import PBIRSClient, DataSource, Schedule, PBIRSConflict
import os

client = PBIRSClient(
    base_url=os.environ["PBIRS_URL"],
    username=os.environ["PBIRS_USER"],
    password=os.environ["PBIRS_PASSWORD"],
    domain=os.environ.get("PBIRS_DOMAIN", ""),
)

# Ensure folder exists
try:
    folder = client.create_folder("/Sales")
except PBIRSConflict:
    folder = client.get_folder("/Sales")

# Deploy report
report = client.upload_powerbi_report(
    folder_path="/Sales",
    file_path="artifacts/Revenue.pbix",
    name="Revenue",
    overwrite=True,
)

# Point at production database
report.set_datasources([
    DataSource(
        "SalesDB",
        f"Server={os.environ['DB_HOST']};Database=Sales;",
        credential_retrieval="Store",
        username=os.environ["DB_USER"],
        password=os.environ["DB_PASSWORD"],
        windows_credentials=False,
    )
])

# Schedule nightly refresh at 02:00
for plan in report.get_cache_refresh_plans():
    plan.delete()

report.create_cache_refresh_plan(
    description="Nightly",
    schedule=Schedule.daily(hour=2),
)

# Grant read access
report.add_user("CORP\\Sales Team", ["Browser"])
```

---

## Testing

```bash
pip install pytest
pytest tests/ -v
```

All tests use `unittest.mock` — no live server required.

---

## License

MIT License
