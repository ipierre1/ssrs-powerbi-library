"""
CI/CD deployment script for PBIRS reports.

Typical pipeline usage:

    # GitLab CI / GitHub Actions environment variables:
    #   PBIRS_URL, PBIRS_USERNAME, PBIRS_PASSWORD, PBIRS_DOMAIN

    python examples/deploy_reports.py

The script:
  1. Connects to the PBIRS server.
  2. Ensures the target folder exists (creates it if missing).
  3. Uploads every .pbix and .rdl file found in a local directory.
  4. Applies environment-specific data source settings.
  5. Sets data model parameters.
  6. Creates (or replaces) a daily cache-refresh plan on each Power BI report.
"""

import os
import sys
from pathlib import Path

from ssrs_library import PBIRSClient, DataSource, Schedule
from ssrs_library.exceptions import PBIRSNotFound, PBIRSConflict


# ------------------------------------------------------------------
# Configuration — adapt these values or drive them from env vars.
# ------------------------------------------------------------------
REPORTS_DIR = Path("./reports")          # local folder containing .pbix / .rdl
TARGET_FOLDER = "/Sales/Deployed"        # destination catalog folder
OVERWRITE = True                         # replace existing reports

# Data source to apply to every uploaded Power BI report
DATASOURCE = DataSource(
    name="SalesDB",
    connection_string=(
        f"Data Source={os.getenv('DB_SERVER', 'prod-srv')};"
        f"Initial Catalog={os.getenv('DB_NAME', 'Sales')}"
    ),
    data_source_type="SQL",
    credential_retrieval="Store",
    username=os.getenv("DB_USERNAME", "svc_report"),
    password=os.getenv("DB_PASSWORD", ""),
    windows_credentials=True,
)

# Data model parameters to apply to every uploaded Power BI report
DATA_MODEL_PARAMS = [
    {"Name": "Environment", "Value": os.getenv("ENV_NAME", "Production")},
]

# Cache-refresh schedule for Power BI reports
REFRESH_SCHEDULE = Schedule.daily(hour=2)   # every night at 02:00


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def ensure_folder(client: PBIRSClient, path: str) -> None:
    """Create *path* (and any missing parent folders) if it doesn't exist."""
    parts = [p for p in path.strip("/").split("/") if p]
    current = ""
    for part in parts:
        current += f"/{part}"
        try:
            client.get_folder(current)
        except PBIRSNotFound:
            try:
                client.create_folder(current)
                print(f"  [folder created] {current}")
            except PBIRSConflict:
                pass  # race condition — already exists


def deploy_pbix(client: PBIRSClient, file: Path, folder: str) -> None:
    """Upload a .pbix file then apply datasource, parameters and schedule."""
    print(f"\n  Deploying Power BI report: {file.name}")

    report = client.upload_powerbi_report(
        folder_path=folder,
        file_path=str(file),
        name=file.stem,
        overwrite=OVERWRITE,
    )
    print(f"    Uploaded → {report.path}")

    # Data source
    try:
        report.set_datasources([DATASOURCE])
        print("    Data source updated.")
    except Exception as exc:
        print(f"    WARNING: could not set datasource — {exc}")

    # Data model parameters
    try:
        report.set_data_model_parameters(DATA_MODEL_PARAMS)
        print("    Data model parameters updated.")
    except Exception as exc:
        print(f"    WARNING: could not set parameters — {exc}")

    # Cache-refresh plan — drop existing plans and create a fresh one.
    try:
        for existing_plan in report.get_cache_refresh_plans():
            existing_plan.delete()
        plan = report.create_cache_refresh_plan(
            description=f"Auto — deployed by CI/CD pipeline",
            schedule=REFRESH_SCHEDULE,
        )
        print(f"    Cache-refresh plan created ({plan.id}).")
    except Exception as exc:
        print(f"    WARNING: could not set cache-refresh plan — {exc}")


def deploy_rdl(client: PBIRSClient, file: Path, folder: str) -> None:
    """Upload a .rdl file."""
    print(f"\n  Deploying paginated report: {file.name}")

    report = client.upload_paginated_report(
        folder_path=folder,
        file_path=str(file),
        name=file.stem,
        overwrite=OVERWRITE,
    )
    print(f"    Uploaded → {report.path}")


# ------------------------------------------------------------------
# Main
# ------------------------------------------------------------------

def main() -> None:
    # Connect
    client = PBIRSClient(
        base_url=os.environ["PBIRS_URL"],
        username=os.environ["PBIRS_USERNAME"],
        password=os.environ["PBIRS_PASSWORD"],
        domain=os.getenv("PBIRS_DOMAIN"),
        verify_ssl=os.getenv("PBIRS_VERIFY_SSL", "true").lower() != "false",
    )

    if not client.test_connection():
        print("ERROR: Cannot reach the PBIRS server.")
        sys.exit(1)

    print(f"Connected to {client}")

    # Ensure the target folder exists
    print(f"\nEnsuring folder: {TARGET_FOLDER}")
    ensure_folder(client, TARGET_FOLDER)

    # Collect report files
    if not REPORTS_DIR.is_dir():
        print(f"ERROR: Reports directory not found: {REPORTS_DIR}")
        sys.exit(1)

    pbix_files = sorted(REPORTS_DIR.glob("*.pbix"))
    rdl_files = sorted(REPORTS_DIR.glob("*.rdl"))

    if not pbix_files and not rdl_files:
        print("No .pbix or .rdl files found — nothing to deploy.")
        sys.exit(0)

    print(f"\nFound {len(pbix_files)} .pbix and {len(rdl_files)} .rdl file(s).")

    errors: list[str] = []

    for file in pbix_files:
        try:
            deploy_pbix(client, file, TARGET_FOLDER)
        except Exception as exc:
            msg = f"{file.name}: {exc}"
            print(f"    ERROR: {msg}")
            errors.append(msg)

    for file in rdl_files:
        try:
            deploy_rdl(client, file, TARGET_FOLDER)
        except Exception as exc:
            msg = f"{file.name}: {exc}"
            print(f"    ERROR: {msg}")
            errors.append(msg)

    # Summary
    total = len(pbix_files) + len(rdl_files)
    print(f"\nDeployment complete — {total - len(errors)}/{total} succeeded.")

    if errors:
        print("Failures:")
        for err in errors:
            print(f"  - {err}")
        sys.exit(1)


if __name__ == "__main__":
    main()
