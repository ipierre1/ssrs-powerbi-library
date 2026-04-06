"""
Examples showing the main patterns of the PBIRS Python library.
"""
from ssrs_library import PBIRSClient, DataSource, Schedule

# ------------------------------------------------------------------
# 1. Connect
# ------------------------------------------------------------------
client = PBIRSClient(
    "http://myserver/reports",
    username="svc_account",
    password="secret",
    domain="CORP",
)

print(client.test_connection())  # True

# ------------------------------------------------------------------
# 2. Folders
# ------------------------------------------------------------------
for folder in client.list_folders("/Sales"):
    print(folder.name, folder.path)

folder = client.create_folder("/Sales/2025", description="FY 2025 reports")
folder.delete()

# ------------------------------------------------------------------
# 3. Power BI reports
# ------------------------------------------------------------------
report = client.get_powerbi_report("/Sales/Revenue Q1")
reports = client.list_powerbi_reports("/Sales")   # folder filter
all_reports = client.list_powerbi_reports()        # whole catalog

report = client.upload_powerbi_report(
    folder_path="/Sales",
    file_path="./Revenue_Q1.pbix",
    name="Revenue Q1",
    overwrite=True,
)
report.delete()

# ------------------------------------------------------------------
# 4. Data sources
# ------------------------------------------------------------------
report = client.get_powerbi_report("/Sales/Revenue Q1")

sources = report.get_datasources()
for ds in sources:
    print(ds.name, ds.connection_string)

# Modify in place and push back
sources[0].connection_string = "Data Source=prod-srv;Initial Catalog=Sales"
sources[0].credential_retrieval = "Store"
sources[0].username = "svc"
sources[0].password = "secret"
sources[0].windows_credentials = True
report.set_datasources(sources)

# Or build a DataSource from scratch
report.set_datasources([
    DataSource(
        name="SalesDB",
        connection_string="Data Source=prod-srv;Initial Catalog=Sales",
        data_source_type="SQL",
        credential_retrieval="Store",
        username="svc",
        password="secret",
        windows_credentials=True,
    )
])

# ------------------------------------------------------------------
# 5. Data model parameters
# ------------------------------------------------------------------
params = report.get_data_model_parameters()
print(params)  # [{"Name": "Env", "Value": "Dev"}, ...]

report.set_data_model_parameters([
    {"Name": "Env", "Value": "Production"},
    {"Name": "MaxRows", "Value": "50000"},
])

# ------------------------------------------------------------------
# 6. Cache refresh plans
# ------------------------------------------------------------------
plans = report.get_cache_refresh_plans()

# --- Every day at 02:00 AM (default hour) ---
plan = report.create_cache_refresh_plan(
    description="Nightly refresh",
    schedule=Schedule.daily(hour=2),
)

# --- Every day at 06:30 AM ---
plan = report.create_cache_refresh_plan(
    description="Early morning refresh",
    schedule=Schedule.daily(hour=6, minute=30),
)

# --- Every 2 days at midnight ---
plan = report.create_cache_refresh_plan(
    description="Every other day",
    schedule=Schedule.daily(hour=0, interval=2),
)

# --- Every Monday and Friday at 08:30 ---
plan = report.create_cache_refresh_plan(
    description="Twice a week",
    schedule=Schedule.weekly(["Monday", "Friday"], hour=8, minute=30),
)

# --- Every Wednesday, bi-weekly at 22:00 ---
plan = report.create_cache_refresh_plan(
    description="Bi-weekly Wednesday evening",
    schedule=Schedule.weekly(["Wednesday"], hour=22, interval=2),
)

# --- 1st of every month at 03:00 ---
plan = report.create_cache_refresh_plan(
    description="Monthly refresh",
    schedule=Schedule.monthly(day=1, hour=3),
)

# --- 15th of January and July at 06:00 (semi-annual) ---
plan = report.create_cache_refresh_plan(
    description="Semi-annual refresh",
    schedule=Schedule.monthly(day=15, hour=6, months=["January", "July"]),
)

# Trigger immediately, update schedule, then clean up
plan.execute()
plan.update(
    description="Updated to weekly",
    schedule=Schedule.weekly(["Monday"], hour=4),
)
plan.delete()

# ------------------------------------------------------------------
# 7. Row-level security (RLS)
# ------------------------------------------------------------------
roles = report.get_data_model_roles()
print([r["ModelRoleName"] for r in roles])

report.set_data_model_role_assignments([
    {"GroupUserName": "CORP\\alice", "Roles": ["Region_West"]},
    {"GroupUserName": "CORP\\bob", "Roles": ["Region_East"]},
])

# ------------------------------------------------------------------
# 8. Paginated (SSRS) reports
# ------------------------------------------------------------------
rdl = client.get_paginated_report("/Finance/Monthly Invoices")
rdl_list = client.list_paginated_reports("/Finance")

rdl = client.upload_paginated_report(
    folder_path="/Finance",
    file_path="./Monthly_Invoices.rdl",
    overwrite=True,
)

params = rdl.get_parameters()
rdl.set_parameters(params)

sources = rdl.get_datasources()
rdl.set_datasources(sources)

plan = rdl.create_cache_refresh_plan(description="Weekly RDL refresh")
plan.delete()

rdl.delete()
