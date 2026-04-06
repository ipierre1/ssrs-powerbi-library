"""
Connection configuration patterns for the PBIRS Python library.

Three common approaches are shown:
  1. Direct credentials (quick scripts / interactive use)
  2. Environment variables (CI/CD pipelines)
  3. .env file (local development)
"""

import os
from ssrs_library import PBIRSClient

# ------------------------------------------------------------------
# 1. Direct credentials
# ------------------------------------------------------------------
client = PBIRSClient(
    base_url="http://myserver/reports",
    username="svc_account",
    password="secret",
    domain="CORP",           # omit when the server is not domain-joined
    verify_ssl=True,         # set False for self-signed certificates (dev only)
    timeout=30,
)

# ------------------------------------------------------------------
# 2. Environment variables  (recommended for CI/CD)
#
#   export PBIRS_URL=http://myserver/reports
#   export PBIRS_USERNAME=svc_account
#   export PBIRS_PASSWORD=secret
#   export PBIRS_DOMAIN=CORP
# ------------------------------------------------------------------
client = PBIRSClient(
    base_url=os.environ["PBIRS_URL"],
    username=os.environ["PBIRS_USERNAME"],
    password=os.environ["PBIRS_PASSWORD"],
    domain=os.getenv("PBIRS_DOMAIN"),       # optional
    verify_ssl=os.getenv("PBIRS_VERIFY_SSL", "true").lower() != "false",
)

# ------------------------------------------------------------------
# 3. .env file (local development with python-dotenv)
#
#   Create a .env file at the repo root:
#       PBIRS_URL=http://myserver/reports
#       PBIRS_USERNAME=svc_account
#       PBIRS_PASSWORD=secret
#       PBIRS_DOMAIN=CORP
# ------------------------------------------------------------------
from dotenv import load_dotenv  # pip install python-dotenv
load_dotenv()

client = PBIRSClient(
    base_url=os.environ["PBIRS_URL"],
    username=os.environ["PBIRS_USERNAME"],
    password=os.environ["PBIRS_PASSWORD"],
    domain=os.getenv("PBIRS_DOMAIN"),
)

# ------------------------------------------------------------------
# Verify the connection before doing any real work
# ------------------------------------------------------------------
if not client.test_connection():
    raise RuntimeError("Cannot reach the PBIRS server — check URL and credentials.")

print("Connected:", client)
