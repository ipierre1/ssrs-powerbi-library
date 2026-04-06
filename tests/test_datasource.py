"""Tests for DataSource."""

import unittest

from ssrs_library._datasource import DataSource


# ---------------------------------------------------------------------------
# Construction
# ---------------------------------------------------------------------------
class TestCreation(unittest.TestCase):

    def test_minimal_fields(self):
        ds = DataSource("MyDB", "Server=x;")
        self.assertEqual(ds.name, "MyDB")
        self.assertEqual(ds.connection_string, "Server=x;")

    def test_default_type_is_sql(self):
        self.assertEqual(DataSource("D", "S").data_source_type, "SQL")

    def test_default_enabled_true(self):
        self.assertTrue(DataSource("D", "S").enabled)

    def test_default_id_none(self):
        self.assertIsNone(DataSource("D", "S").id)

    def test_default_description_none(self):
        self.assertIsNone(DataSource("D", "S").description)

    def test_default_credential_retrieval_none(self):
        self.assertEqual(DataSource("D", "S").credential_retrieval, "None")

    def test_default_username_none(self):
        self.assertIsNone(DataSource("D", "S").username)

    def test_default_password_none(self):
        self.assertIsNone(DataSource("D", "S").password)

    def test_default_windows_credentials_true(self):
        self.assertTrue(DataSource("D", "S").windows_credentials)

    def test_full_construction(self):
        ds = DataSource(
            name="FullDB",
            connection_string="Server=y;",
            data_source_type="OLEDB",
            enabled=False,
            id="ds-99",
            description="Full DS",
            credential_retrieval="Store",
            username="svc",
            password="secret",
            windows_credentials=False,
        )
        self.assertEqual(ds.data_source_type, "OLEDB")
        self.assertFalse(ds.enabled)
        self.assertEqual(ds.id, "ds-99")
        self.assertEqual(ds.description, "Full DS")
        self.assertEqual(ds.credential_retrieval, "Store")
        self.assertEqual(ds.username, "svc")
        self.assertEqual(ds.password, "secret")
        self.assertFalse(ds.windows_credentials)

    def test_repr_contains_name(self):
        self.assertIn("MyDB", repr(DataSource("MyDB", "S")))

    def test_repr_contains_credential_retrieval(self):
        ds = DataSource("D", "S", credential_retrieval="Store")
        self.assertIn("Store", repr(ds))


# ---------------------------------------------------------------------------
# from_api
# ---------------------------------------------------------------------------
class TestFromApi(unittest.TestCase):

    def test_minimal_api_data(self):
        ds = DataSource.from_api({"Name": "DB", "ConnectionString": "Server=x;"})
        self.assertEqual(ds.name, "DB")
        self.assertEqual(ds.connection_string, "Server=x;")
        self.assertEqual(ds.data_source_type, "SQL")
        self.assertTrue(ds.enabled)
        self.assertEqual(ds.credential_retrieval, "None")
        self.assertIsNone(ds.id)
        self.assertIsNone(ds.username)

    def test_with_all_fields(self):
        data = {
            "Id": "ds-1",
            "Name": "OracleDB",
            "ConnectionString": "Data Source=ora;",
            "DataSourceType": "Oracle",
            "Enabled": False,
            "CredentialRetrieval": "Integrated",
            "Description": "Oracle connection",
        }
        ds = DataSource.from_api(data)
        self.assertEqual(ds.id, "ds-1")
        self.assertEqual(ds.data_source_type, "Oracle")
        self.assertFalse(ds.enabled)
        self.assertEqual(ds.credential_retrieval, "Integrated")
        self.assertEqual(ds.description, "Oracle connection")

    def test_with_stored_windows_credentials(self):
        data = {
            "Name": "DB",
            "ConnectionString": "Server=x;",
            "CredentialRetrieval": "Store",
            "CredentialsInServer": {
                "UserName": "svc",
                "Password": "pass",
                "WindowsCredentials": True,
            },
        }
        ds = DataSource.from_api(data)
        self.assertEqual(ds.credential_retrieval, "Store")
        self.assertEqual(ds.username, "svc")
        self.assertEqual(ds.password, "pass")
        self.assertTrue(ds.windows_credentials)

    def test_with_stored_sql_credentials(self):
        data = {
            "Name": "DB",
            "ConnectionString": "Server=x;",
            "CredentialRetrieval": "Store",
            "CredentialsInServer": {
                "UserName": "sa",
                "Password": "pw",
                "WindowsCredentials": False,
            },
        }
        ds = DataSource.from_api(data)
        self.assertFalse(ds.windows_credentials)

    def test_credentials_in_server_null_does_not_crash(self):
        """API sometimes returns CredentialsInServer: null."""
        data = {
            "Name": "DB",
            "ConnectionString": "Server=x;",
            "CredentialRetrieval": "None",
            "CredentialsInServer": None,
        }
        ds = DataSource.from_api(data)
        self.assertIsNone(ds.username)

    def test_missing_optional_fields_use_defaults(self):
        ds = DataSource.from_api({})
        self.assertEqual(ds.name, "")
        self.assertEqual(ds.connection_string, "")
        self.assertTrue(ds.enabled)


# ---------------------------------------------------------------------------
# to_api
# ---------------------------------------------------------------------------
class TestToApi(unittest.TestCase):

    def test_always_contains_required_keys(self):
        payload = DataSource("D", "S").to_api()
        for key in (
            "Name",
            "ConnectionString",
            "DataSourceType",
            "Enabled",
            "CredentialRetrieval",
        ):
            self.assertIn(key, payload)

    def test_no_id_when_none(self):
        self.assertNotIn("Id", DataSource("D", "S").to_api())

    def test_id_present_when_set(self):
        self.assertIn("Id", DataSource("D", "S", id="ds-1").to_api())
        self.assertEqual(DataSource("D", "S", id="ds-1").to_api()["Id"], "ds-1")

    def test_no_description_when_none(self):
        self.assertNotIn("Description", DataSource("D", "S").to_api())

    def test_description_present_when_set(self):
        payload = DataSource("D", "S", description="desc").to_api()
        self.assertEqual(payload["Description"], "desc")

    def test_no_credentials_in_server_for_none_retrieval(self):
        self.assertNotIn(
            "CredentialsInServer",
            DataSource("D", "S", credential_retrieval="None").to_api(),
        )

    def test_no_credentials_in_server_for_integrated(self):
        self.assertNotIn(
            "CredentialsInServer",
            DataSource("D", "S", credential_retrieval="Integrated").to_api(),
        )

    def test_credentials_in_server_for_store_with_username(self):
        ds = DataSource(
            "D",
            "S",
            credential_retrieval="Store",
            username="svc",
            password="pw",
            windows_credentials=True,
        )
        payload = ds.to_api()
        self.assertIn("CredentialsInServer", payload)
        creds = payload["CredentialsInServer"]
        self.assertEqual(creds["UserName"], "svc")
        self.assertEqual(creds["Password"], "pw")
        self.assertTrue(creds["WindowsCredentials"])

    def test_no_credentials_in_server_for_store_without_username(self):
        """Store retrieval but no username → omit block."""
        ds = DataSource("D", "S", credential_retrieval="Store")
        self.assertNotIn("CredentialsInServer", ds.to_api())

    def test_enabled_reflected(self):
        self.assertFalse(DataSource("D", "S", enabled=False).to_api()["Enabled"])

    def test_type_reflected(self):
        self.assertEqual(
            DataSource("D", "S", data_source_type="Oracle").to_api()["DataSourceType"],
            "Oracle",
        )

    def test_roundtrip_from_api(self):
        """from_api → to_api should preserve key fields."""
        original = {
            "Id": "ds-1",
            "Name": "DB",
            "ConnectionString": "Server=x;",
            "DataSourceType": "SQL",
            "Enabled": True,
            "CredentialRetrieval": "Store",
            "CredentialsInServer": {
                "UserName": "svc",
                "Password": "pw",
                "WindowsCredentials": True,
            },
        }
        ds = DataSource.from_api(original)
        payload = ds.to_api()
        self.assertEqual(payload["Id"], "ds-1")
        self.assertEqual(payload["Name"], "DB")
        self.assertEqual(payload["CredentialsInServer"]["UserName"], "svc")


if __name__ == "__main__":
    unittest.main(verbosity=2)
