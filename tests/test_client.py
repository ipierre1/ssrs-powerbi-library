"""Tests for PBIRSClient."""

import os
import tempfile
import unittest
from unittest.mock import Mock, patch

from tests.helpers import make_response
from ssrs_library import PBIRSClient, PowerBIReport, PaginatedReport, Folder
from ssrs_library.exceptions import (
    PBIRSAuthError,
    PBIRSConflict,
    PBIRSError,
    PBIRSNotFound,
)

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------
FOLDER_DATA = {"Id": "f-1", "Name": "Sales", "Path": "/Sales", "Description": ""}
REPORT_DATA = {"Id": "r-1", "Name": "Revenue", "Path": "/Sales/Revenue"}
RDL_DATA = {"Id": "rdl-1", "Name": "Monthly", "Path": "/Finance/Monthly"}


# ---------------------------------------------------------------------------
# Initialisation
# ---------------------------------------------------------------------------
class TestPBIRSClientInit(unittest.TestCase):

    def test_base_url_stored(self):
        c = PBIRSClient("http://srv/reports")
        self.assertEqual(c._base_url, "http://srv/reports")

    def test_api_url_built(self):
        c = PBIRSClient("http://srv/reports")
        self.assertEqual(c._api_url, "http://srv/reports/api/v2.0")

    def test_trailing_slash_stripped(self):
        c = PBIRSClient("http://srv/reports/")
        self.assertEqual(c._base_url, "http://srv/reports")

    def test_no_auth_when_no_credentials(self):
        c = PBIRSClient("http://srv/reports")
        self.assertIsNone(c._session.auth)

    def test_ntlm_auth_set_with_username_password(self):
        c = PBIRSClient("http://srv/reports", username="u", password="p")
        self.assertIsNotNone(c._session.auth)

    def test_ntlm_auth_set_with_domain(self):
        c = PBIRSClient("http://srv/reports", username="u", password="p", domain="DOM")
        self.assertIsNotNone(c._session.auth)

    def test_default_verify_ssl(self):
        self.assertTrue(PBIRSClient("http://srv/reports")._verify_ssl)

    def test_default_timeout(self):
        self.assertEqual(PBIRSClient("http://srv/reports")._timeout, 30)

    def test_custom_verify_ssl(self):
        self.assertFalse(PBIRSClient("http://srv/reports", verify_ssl=False)._verify_ssl)

    def test_custom_timeout(self):
        self.assertEqual(PBIRSClient("http://srv/reports", timeout=60)._timeout, 60)

    def test_repr(self):
        self.assertIn("http://srv/reports", repr(PBIRSClient("http://srv/reports")))


# ---------------------------------------------------------------------------
# _encode_path
# ---------------------------------------------------------------------------
class TestEncodePath(unittest.TestCase):

    def test_adds_leading_slash(self):
        self.assertEqual(PBIRSClient._encode_path("Sales"), "/Sales")

    def test_keeps_leading_slash(self):
        self.assertEqual(PBIRSClient._encode_path("/Sales"), "/Sales")

    def test_encodes_spaces(self):
        self.assertIn("%20", PBIRSClient._encode_path("/My Report"))

    def test_keeps_inner_slashes(self):
        result = PBIRSClient._encode_path("/Sales/Revenue Q1")
        self.assertIn("/Sales/", result)
        self.assertIn("%20", result)

    def test_encodes_ampersand(self):
        self.assertIn("%26", PBIRSClient._encode_path("/A & B"))


# ---------------------------------------------------------------------------
# _request
# ---------------------------------------------------------------------------
class TestRequest(unittest.TestCase):

    def setUp(self):
        self.client = PBIRSClient("http://srv/reports")
        patcher = patch.object(self.client._session, "request")
        self.mock_req = patcher.start()
        self.addCleanup(patcher.stop)

    def test_200_returns_json(self):
        self.mock_req.return_value = make_response(200, {"key": "val"})
        self.assertEqual(self.client._request("GET", "System"), {"key": "val"})

    def test_204_returns_none(self):
        self.mock_req.return_value = make_response(204)
        self.assertIsNone(self.client._request("DELETE", "Folders(x)"))

    def test_empty_content_returns_none(self):
        r = make_response(200)
        r.content = b""
        self.mock_req.return_value = r
        self.assertIsNone(self.client._request("GET", "Folders(x)"))

    def test_401_raises_auth_error(self):
        self.mock_req.return_value = make_response(401)
        with self.assertRaises(PBIRSAuthError):
            self.client._request("GET", "System")

    def test_403_raises_auth_error(self):
        self.mock_req.return_value = make_response(403)
        with self.assertRaises(PBIRSAuthError):
            self.client._request("GET", "System")

    def test_404_raises_not_found(self):
        self.mock_req.return_value = make_response(404)
        with self.assertRaises(PBIRSNotFound) as ctx:
            self.client._request("GET", "Folders(bad)")
        self.assertEqual(ctx.exception.status_code, 404)

    def test_409_raises_conflict(self):
        self.mock_req.return_value = make_response(409)
        with self.assertRaises(PBIRSConflict) as ctx:
            self.client._request("POST", "Folders")
        self.assertEqual(ctx.exception.status_code, 409)

    def test_500_raises_pbirs_error(self):
        self.mock_req.return_value = make_response(500)
        with self.assertRaises(PBIRSError):
            self.client._request("GET", "System")

    def test_url_built_correctly(self):
        self.mock_req.return_value = make_response(200, {})
        self.client._request("GET", "System")
        url = self.mock_req.call_args[0][1]
        self.assertEqual(url, "http://srv/reports/api/v2.0/System")

    def test_url_leading_slash_on_endpoint_stripped(self):
        self.mock_req.return_value = make_response(200, {})
        self.client._request("GET", "/System")
        url = self.mock_req.call_args[0][1]
        self.assertFalse(url.endswith("//System"))


# ---------------------------------------------------------------------------
# test_connection
# ---------------------------------------------------------------------------
class TestConnection(unittest.TestCase):

    def setUp(self):
        self.client = PBIRSClient("http://srv/reports")
        patcher = patch.object(self.client._session, "request")
        self.mock_req = patcher.start()
        self.addCleanup(patcher.stop)

    def test_returns_true_on_success(self):
        self.mock_req.return_value = make_response(200, {})
        self.assertTrue(self.client.test_connection())

    def test_returns_false_on_401(self):
        self.mock_req.return_value = make_response(401)
        self.assertFalse(self.client.test_connection())

    def test_returns_false_on_404(self):
        self.mock_req.return_value = make_response(404)
        self.assertFalse(self.client.test_connection())

    def test_returns_false_on_500(self):
        self.mock_req.return_value = make_response(500)
        self.assertFalse(self.client.test_connection())


# ---------------------------------------------------------------------------
# Folders
# ---------------------------------------------------------------------------
class TestFolderMethods(unittest.TestCase):

    def setUp(self):
        self.client = PBIRSClient("http://srv/reports")
        patcher = patch.object(self.client, "_request")
        self.mock = patcher.start()
        self.addCleanup(patcher.stop)

    def test_get_folder_returns_folder(self):
        self.mock.return_value = FOLDER_DATA
        folder = self.client.get_folder("/Sales")
        self.assertIsInstance(folder, Folder)
        self.assertEqual(folder.id, "f-1")
        self.assertEqual(folder.name, "Sales")

    def test_get_folder_encodes_path(self):
        self.mock.return_value = {**FOLDER_DATA, "Path": "/My Folder"}
        self.client.get_folder("/My Folder")
        endpoint = self.mock.call_args[0][1]
        self.assertIn("%20", endpoint)

    def test_get_folder_calls_correct_endpoint(self):
        self.mock.return_value = FOLDER_DATA
        self.client.get_folder("/Sales")
        self.mock.assert_called_once_with("GET", "Folders(Path='/Sales')")

    def test_create_folder_posts_correct_payload(self):
        self.mock.return_value = {
            "Id": "f-2", "Name": "2025", "Path": "/Sales/2025", "Description": "FY"
        }
        folder = self.client.create_folder("/Sales/2025", description="FY")
        self.assertIsInstance(folder, Folder)
        call_method, call_endpoint = self.mock.call_args[0]
        self.assertEqual(call_method, "POST")
        self.assertEqual(call_endpoint, "Folders")
        payload = self.mock.call_args[1]["json"]
        self.assertEqual(payload["Name"], "2025")
        self.assertEqual(payload["Description"], "FY")

    def test_list_folders_returns_only_folders(self):
        self.mock.side_effect = [
            FOLDER_DATA,  # get_folder call
            {"value": [
                {"Id": "f-2", "Name": "Sub", "Path": "/Sales/Sub", "Type": "Folder"},
                {"Id": "r-1", "Name": "Rep", "Path": "/Sales/Rep", "Type": "PowerBIReport"},
            ]},
        ]
        result = self.client.list_folders("/Sales")
        self.assertEqual(len(result), 1)
        self.assertIsInstance(result[0], Folder)
        self.assertEqual(result[0].name, "Sub")

    def test_list_folders_empty(self):
        self.mock.side_effect = [FOLDER_DATA, {"value": []}]
        self.assertEqual(self.client.list_folders("/Sales"), [])


# ---------------------------------------------------------------------------
# Power BI reports
# ---------------------------------------------------------------------------
class TestPowerBIReportMethods(unittest.TestCase):

    def setUp(self):
        self.client = PBIRSClient("http://srv/reports")
        patcher = patch.object(self.client, "_request")
        self.mock = patcher.start()
        self.addCleanup(patcher.stop)

    def test_get_powerbi_report_returns_object(self):
        self.mock.return_value = REPORT_DATA
        report = self.client.get_powerbi_report("/Sales/Revenue")
        self.assertIsInstance(report, PowerBIReport)
        self.assertEqual(report.id, "r-1")

    def test_get_powerbi_report_encodes_path(self):
        self.mock.return_value = REPORT_DATA
        self.client.get_powerbi_report("/Sales/Revenue Q1")
        endpoint = self.mock.call_args[0][1]
        self.assertIn("%20", endpoint)

    def test_list_powerbi_reports_all(self):
        self.mock.return_value = {"value": [REPORT_DATA]}
        reports = self.client.list_powerbi_reports()
        self.assertEqual(len(reports), 1)
        self.assertIsInstance(reports[0], PowerBIReport)
        self.mock.assert_called_once_with("GET", "PowerBIReports")

    def test_list_powerbi_reports_by_folder_filters_type(self):
        self.mock.side_effect = [
            FOLDER_DATA,
            {"value": [
                {**REPORT_DATA, "Type": "PowerBIReport"},
                {"Id": "f-2", "Name": "Sub", "Path": "/Sales/Sub", "Type": "Folder"},
            ]},
        ]
        reports = self.client.list_powerbi_reports("/Sales")
        self.assertEqual(len(reports), 1)
        self.assertIsInstance(reports[0], PowerBIReport)

    def test_list_powerbi_reports_by_folder_empty(self):
        self.mock.side_effect = [FOLDER_DATA, {"value": []}]
        self.assertEqual(self.client.list_powerbi_reports("/Sales"), [])

    def test_upload_small_pbix_uses_base64_post(self):
        with tempfile.NamedTemporaryFile(suffix=".pbix", delete=False) as f:
            f.write(b"\x00" * 100)
            tmp = f.name
        try:
            self.mock.return_value = REPORT_DATA
            report = self.client.upload_powerbi_report("/Sales", tmp, name="Revenue")
            self.assertIsInstance(report, PowerBIReport)
            method, endpoint = self.mock.call_args[0]
            self.assertEqual(method, "POST")
            self.assertEqual(endpoint, "PowerBIReports")
            payload = self.mock.call_args[1]["json"]
            self.assertEqual(payload["Name"], "Revenue")
            self.assertEqual(payload["@odata.type"], "#Model.PowerBIReport")
            self.assertIn("Content", payload)  # base64-encoded
        finally:
            os.unlink(tmp)

    def test_upload_pbix_default_name_from_filename(self):
        with tempfile.NamedTemporaryFile(
            suffix=".pbix", prefix="MyReport_", delete=False
        ) as f:
            f.write(b"\x00" * 10)
            tmp = f.name
        try:
            self.mock.return_value = REPORT_DATA
            self.client.upload_powerbi_report("/Sales", tmp)
            payload = self.mock.call_args[1]["json"]
            expected_name = os.path.splitext(os.path.basename(tmp))[0]
            self.assertEqual(payload["Name"], expected_name)
        finally:
            os.unlink(tmp)

    @patch("ssrs_library.client._MULTIPART_THRESHOLD", 10)
    def test_upload_large_pbix_calls_multipart(self):
        with tempfile.NamedTemporaryFile(suffix=".pbix", delete=False) as f:
            f.write(b"\x00" * 50)   # 50 bytes > patched threshold of 10
            tmp = f.name
        try:
            with patch.object(
                self.client, "_upload_pbix_multipart", return_value=REPORT_DATA
            ) as mock_multi:
                report = self.client.upload_powerbi_report("/Sales", tmp, name="Big")
                mock_multi.assert_called_once()
            self.assertIsInstance(report, PowerBIReport)
        finally:
            os.unlink(tmp)

    def test_upload_pbix_overwrite_patches_existing(self):
        existing_data = {**REPORT_DATA, "Id": "r-existing"}
        # Calls: get_powerbi_report (GET), PATCH
        self.mock.side_effect = [existing_data, existing_data]
        with tempfile.NamedTemporaryFile(suffix=".pbix", delete=False) as f:
            f.write(b"\x00" * 10)
            tmp = f.name
        try:
            report = self.client.upload_powerbi_report(
                "/Sales", tmp, name="Revenue", overwrite=True
            )
            # Second call should be a PATCH
            patch_call = self.mock.call_args_list[1]
            self.assertEqual(patch_call[0][0], "PATCH")
        finally:
            os.unlink(tmp)


# ---------------------------------------------------------------------------
# Paginated reports
# ---------------------------------------------------------------------------
class TestPaginatedReportMethods(unittest.TestCase):

    def setUp(self):
        self.client = PBIRSClient("http://srv/reports")
        patcher = patch.object(self.client, "_request")
        self.mock = patcher.start()
        self.addCleanup(patcher.stop)

    def test_get_paginated_report_returns_object(self):
        self.mock.return_value = RDL_DATA
        report = self.client.get_paginated_report("/Finance/Monthly")
        self.assertIsInstance(report, PaginatedReport)
        self.assertEqual(report.id, "rdl-1")

    def test_list_paginated_reports_all(self):
        self.mock.return_value = {"value": [RDL_DATA]}
        reports = self.client.list_paginated_reports()
        self.assertEqual(len(reports), 1)
        self.assertIsInstance(reports[0], PaginatedReport)
        self.mock.assert_called_once_with("GET", "Reports")

    def test_list_paginated_reports_by_folder_filters_type(self):
        folder_data = {"Id": "ff-1", "Name": "Finance", "Path": "/Finance"}
        self.mock.side_effect = [
            folder_data,
            {"value": [
                {**RDL_DATA, "Type": "Report"},
                {"Id": "f-2", "Name": "Sub", "Path": "/Finance/Sub", "Type": "Folder"},
            ]},
        ]
        reports = self.client.list_paginated_reports("/Finance")
        self.assertEqual(len(reports), 1)
        self.assertIsInstance(reports[0], PaginatedReport)

    def test_upload_paginated_report(self):
        with tempfile.NamedTemporaryFile(suffix=".rdl", delete=False) as f:
            f.write(b"<Report />")
            tmp = f.name
        try:
            self.mock.return_value = RDL_DATA
            report = self.client.upload_paginated_report(
                "/Finance", tmp, name="Monthly"
            )
            self.assertIsInstance(report, PaginatedReport)
            method, endpoint = self.mock.call_args[0]
            self.assertEqual(method, "POST")
            self.assertEqual(endpoint, "Reports")
            payload = self.mock.call_args[1]["json"]
            self.assertEqual(payload["Name"], "Monthly")
            self.assertEqual(payload["@odata.type"], "#Model.Report")
            self.assertIn("Content", payload)
        finally:
            os.unlink(tmp)

    def test_upload_paginated_report_default_name(self):
        with tempfile.NamedTemporaryFile(
            suffix=".rdl", prefix="Invoice_", delete=False
        ) as f:
            f.write(b"<Report />")
            tmp = f.name
        try:
            self.mock.return_value = RDL_DATA
            self.client.upload_paginated_report("/Finance", tmp)
            payload = self.mock.call_args[1]["json"]
            expected = os.path.splitext(os.path.basename(tmp))[0]
            self.assertEqual(payload["Name"], expected)
        finally:
            os.unlink(tmp)

    def test_upload_paginated_report_overwrite_patches_existing(self):
        existing = {**RDL_DATA, "Id": "rdl-existing"}
        self.mock.side_effect = [existing, existing]
        with tempfile.NamedTemporaryFile(suffix=".rdl", delete=False) as f:
            f.write(b"<Report />")
            tmp = f.name
        try:
            self.client.upload_paginated_report(
                "/Finance", tmp, name="Monthly", overwrite=True
            )
            patch_call = self.mock.call_args_list[1]
            self.assertEqual(patch_call[0][0], "PATCH")
        finally:
            os.unlink(tmp)


if __name__ == "__main__":
    unittest.main(verbosity=2)
