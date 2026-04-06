"""
Row-Level Security (RLS) management examples.

RLS in PBIRS is managed directly on each Power BI report through its
data-model roles.  There is no separate security manager — everything
goes through the :class:`~ssrs_library.PowerBIReport` object.

Covered here:
  1. Inspecting available RLS roles
  2. Reading current user assignments
  3. Assigning users to roles
  4. Removing a user from all roles
  5. Copying RLS assignments from one report to another (migration)
  6. Applying a standard security template to multiple reports
"""

import os
from ssrs_library import PBIRSClient
from ssrs_library.exceptions import PBIRSNotFound


client = PBIRSClient(
    base_url=os.environ["PBIRS_URL"],
    username=os.environ["PBIRS_USERNAME"],
    password=os.environ["PBIRS_PASSWORD"],
    domain=os.getenv("PBIRS_DOMAIN"),
    verify_ssl=False,   # set True in production
)


# ------------------------------------------------------------------
# 1. Inspect available RLS roles defined in the data model
# ------------------------------------------------------------------
report = client.get_powerbi_report("/Sales/Revenue")

roles = report.get_data_model_roles()
print("Available roles:")
for role in roles:
    print(f"  - {role['ModelRoleName']}")


# ------------------------------------------------------------------
# 2. Read current user → role assignments
# ------------------------------------------------------------------
assignments = report.get_data_model_role_assignments()
print("\nCurrent assignments:")
for a in assignments:
    print(f"  {a['GroupUserName']} → {a['Roles']}")


# ------------------------------------------------------------------
# 3. Assign users to roles (full replace)
#
#    set_data_model_role_assignments() replaces ALL existing
#    assignments, so always pass the complete desired state.
# ------------------------------------------------------------------
report.set_data_model_role_assignments([
    {"GroupUserName": "CORP\\alice",     "Roles": ["Region_West"]},
    {"GroupUserName": "CORP\\bob",       "Roles": ["Region_East"]},
    {"GroupUserName": "CORP\\managers",  "Roles": ["Region_West", "Region_East"]},
])
print("\nAssignments updated.")


# ------------------------------------------------------------------
# 4. Add a single user without touching the others
#    (read → modify → write pattern)
# ------------------------------------------------------------------
def add_user_to_roles(report, username: str, roles: list[str]) -> None:
    """Add *username* to *roles*, keeping all existing assignments intact."""
    current = report.get_data_model_role_assignments()

    # Find existing entry for this user (if any).
    for entry in current:
        if entry["GroupUserName"].lower() == username.lower():
            # Merge roles (deduplicated).
            entry["Roles"] = list(set(entry["Roles"]) | set(roles))
            report.set_data_model_role_assignments(current)
            return

    # User not yet present — append a new entry.
    current.append({"GroupUserName": username, "Roles": roles})
    report.set_data_model_role_assignments(current)


add_user_to_roles(report, "CORP\\charlie", ["Region_West"])
print("charlie added to Region_West.")


# ------------------------------------------------------------------
# 5. Remove a user from all roles
#    (read → filter out → write pattern)
# ------------------------------------------------------------------
def remove_user(report, username: str) -> None:
    """Remove *username* from every role on *report*."""
    current = report.get_data_model_role_assignments()
    updated = [a for a in current
               if a["GroupUserName"].lower() != username.lower()]
    report.set_data_model_role_assignments(updated)


remove_user(report, "CORP\\charlie")
print("charlie removed.")


# ------------------------------------------------------------------
# 6. Copy RLS assignments between two reports (migration / promotion)
# ------------------------------------------------------------------
def migrate_rls(client: PBIRSClient, source_path: str, target_path: str) -> None:
    """
    Copy all RLS role assignments from *source_path* to *target_path*.

    Roles are matched by name; any role that doesn't exist on the
    target model is silently skipped.
    """
    try:
        source = client.get_powerbi_report(source_path)
    except PBIRSNotFound:
        print(f"Source report not found: {source_path}")
        return

    try:
        target = client.get_powerbi_report(target_path)
    except PBIRSNotFound:
        print(f"Target report not found: {target_path}")
        return

    source_assignments = source.get_data_model_role_assignments()
    if not source_assignments:
        print("No RLS assignments on source — nothing to migrate.")
        return

    # Filter to roles that actually exist on the target model.
    target_role_names = {r["ModelRoleName"]
                         for r in target.get_data_model_roles()}
    migrated = []
    for entry in source_assignments:
        valid_roles = [r for r in entry["Roles"] if r in target_role_names]
        if valid_roles:
            migrated.append({"GroupUserName": entry["GroupUserName"],
                              "Roles": valid_roles})

    target.set_data_model_role_assignments(migrated)
    print(f"Migrated {len(migrated)} assignment(s) from {source_path} to {target_path}.")


migrate_rls(client, "/Sales/Revenue_DEV", "/Sales/Revenue")


# ------------------------------------------------------------------
# 7. Apply a standard security template to several reports at once
# ------------------------------------------------------------------
SECURITY_TEMPLATE = [
    {"GroupUserName": "CORP\\team_west",     "Roles": ["Region_West"]},
    {"GroupUserName": "CORP\\team_east",     "Roles": ["Region_East"]},
    {"GroupUserName": "CORP\\sales_managers","Roles": ["Region_West", "Region_East"]},
]

reports_to_secure = [
    "/Sales/Revenue",
    "/Sales/Pipeline",
    "/Sales/Forecasts",
]

print("\nApplying security template:")
for path in reports_to_secure:
    try:
        r = client.get_powerbi_report(path)
        r.set_data_model_role_assignments(SECURITY_TEMPLATE)
        print(f"  OK  {path}")
    except PBIRSNotFound:
        print(f"  SKIP (not found)  {path}")
    except Exception as exc:
        print(f"  ERROR  {path}: {exc}")
