#!/usr/bin/env python3
"""
Tests unitaires pour le gestionnaire de sécurité SSRS
"""

import unittest
from unittest.mock import Mock, patch, MagicMock
from ssrs_library import (
    SSRSRestClient,
    SSRSSecurityManager,
    SecurityRoleType,
    PermissionType,
    RsPolicy,
    DataModelRole,
    DataModelRoleAssignment,
)

import os
from dotenv import load_dotenv

load_dotenv()


class TestSSRSSecurityManager(unittest.TestCase):
    """Test cases pour SSRSSecurityManager"""

    def setUp(self):
        """Configuration des tests"""
        self.mock_client = Mock(spec=SSRSRestClient)
        self.security_manager = SSRSSecurityManager(self.mock_client)

    def test_manager_initialization(self):
        """Test de l'initialisation du gestionnaire"""
        self.assertEqual(self.security_manager.client, self.mock_client)

    def test_invalid_client_initialization(self):
        """Test d'initialisation avec un client invalide"""
        with self.assertRaises(TypeError):
            SSRSSecurityManager("invalid_client")

    def test_get_report_id_success(self):
        """Test de récupération d'ID de rapport - succès"""
        # Mock de la réponse
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "value": [
                {"Id": "test-report-id", "Path": "/Test/Report", "Name": "Report"}
            ]
        }
        self.mock_client._make_request.return_value = mock_response

        result = self.security_manager.get_report_id("/Test/Report")

        self.assertEqual(result, "test-report-id")
        self.mock_client._make_request.assert_called_once()

    def test_get_report_id_not_found(self):
        """Test de récupération d'ID de rapport - non trouvé"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"value": []}
        self.mock_client._make_request.return_value = mock_response

        result = self.security_manager.get_report_id("/Test/NonExistent")

        self.assertIsNone(result)

    def test_get_data_model_roles_success(self):
        """Test de récupération des rôles du modèle de données"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "value": [
                {"ModelRoleName": "Sales Manager", "ModelRoleId": "role-id-1"},
                {"ModelRoleName": "Sales Rep", "ModelRoleId": "role-id-2"},
            ]
        }
        self.mock_client._make_request.return_value = mock_response

        result = self.security_manager.get_data_model_roles("report-id")

        expected = {"Sales Manager": "role-id-1", "Sales Rep": "role-id-2"}
        self.assertEqual(result, expected)

    def test_get_data_model_role_assignments_success(self):
        """Test de récupération des assignations de rôles"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "value": [
                {"GroupUserName": "DOMAIN\\user1", "DataModelRoles": ["role-id-1"]},
                {
                    "GroupUserName": "DOMAIN\\user2",
                    "DataModelRoles": ["role-id-1", "role-id-2"],
                },
            ]
        }
        self.mock_client._make_request.return_value = mock_response

        result = self.security_manager.get_data_model_role_assignments("report-id")

        self.assertEqual(len(result), 2)
        self.assertEqual(result[0]["GroupUserName"], "DOMAIN\\user1")
        self.assertEqual(result[1]["DataModelRoles"], ["role-id-1", "role-id-2"])

    def test_set_data_model_role_assignments_success(self):
        """Test de définition des assignations de rôles"""
        mock_response = Mock()
        mock_response.status_code = 200
        self.mock_client._make_request.return_value = mock_response

        assignments = [
            {"GroupUserName": "DOMAIN\\user1", "DataModelRoles": ["role-id-1"]}
        ]

        result = self.security_manager.set_data_model_role_assignments(
            "report-id", assignments
        )

        self.assertTrue(result)
        self.mock_client._make_request.assert_called_once_with(
            "PUT",
            "PowerBIReports(report-id)/DataModelRoleAssignments",
            json=assignments,
        )

    def test_create_role_mapping(self):
        """Test de création du mapping de rôles"""
        source_roles = {
            "Manager": "source-role-1",
            "Employee": "source-role-2",
            "Admin": "source-role-3",
        }

        target_roles = {
            "Manager": "target-role-1",
            "Employee": "target-role-2",
            # Admin manquant intentionnellement
        }

        result = self.security_manager.create_role_mapping(source_roles, target_roles)

        expected = {"source-role-1": "target-role-1", "source-role-2": "target-role-2"}
        self.assertEqual(result, expected)

    @patch.object(SSRSSecurityManager, "get_report_id")
    @patch.object(SSRSSecurityManager, "get_data_model_roles")
    @patch.object(SSRSSecurityManager, "get_data_model_role_assignments")
    @patch.object(SSRSSecurityManager, "set_data_model_role_assignments")
    def test_migrate_data_model_role_assignments_success(
        self, mock_set, mock_get_assignments, mock_get_roles, mock_get_id
    ):
        """Test de migration des assignations RLS - succès"""
        # Configuration des mocks
        mock_get_id.side_effect = ["source-id", "target-id"]
        mock_get_roles.side_effect = [
            {"Manager": "source-role-1"},
            {"Manager": "target-role-1"},
        ]
        mock_get_assignments.return_value = [
            {"GroupUserName": "DOMAIN\\user1", "DataModelRoles": ["source-role-1"]}
        ]
        mock_set.return_value = True

        result = self.security_manager.migrate_data_model_role_assignments(
            "/source/report", "/target/report"
        )

        self.assertTrue(result)
        mock_set.assert_called_once()

    def test_get_catalog_item_policies_success(self):
        """Test de récupération des politiques d'élément de catalogue"""
        # Mock du client get_catalog_item
        mock_item = Mock()
        mock_item.id = "item-id"
        self.mock_client.get_catalog_item.return_value = mock_item

        # Mock de la réponse des politiques
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "value": [{"GroupUserName": "DOMAIN\\user1", "Roles": ["Browser"]}]
        }
        self.mock_client._make_request.return_value = mock_response

        result = self.security_manager.get_catalog_item_policies("/test/item")

        self.assertIsNotNone(result)
        self.assertIn("value", result)

    def test_set_catalog_item_policies_success(self):
        """Test de définition des politiques d'élément de catalogue"""
        # Mock du client get_catalog_item
        mock_item = Mock()
        mock_item.id = "item-id"
        self.mock_client.get_catalog_item.return_value = mock_item

        # Mock de la réponse
        mock_response = Mock()
        mock_response.status_code = 200
        self.mock_client._make_request.return_value = mock_response

        policies = {
            "@odata.context": "context",
            "Id": "should-be-removed",
            "value": [{"GroupUserName": "DOMAIN\\user1", "Roles": ["Browser"]}],
        }

        result = self.security_manager.set_catalog_item_policies("/test/item", policies)

        self.assertTrue(result)

        # Vérifier que les champs métadonnées ont été supprimés
        call_args = self.mock_client._make_request.call_args
        sent_policies = call_args[1]["json"]
        self.assertNotIn("@odata.context", sent_policies)
        self.assertNotIn("Id", sent_policies)

    @patch.object(SSRSSecurityManager, "get_catalog_item_policies")
    @patch.object(SSRSSecurityManager, "set_catalog_item_policies")
    def test_migrate_catalog_item_policies_success(self, mock_set, mock_get):
        """Test de migration des politiques d'élément de catalogue"""
        mock_policies = {"value": [{"GroupUserName": "DOMAIN\\user1"}]}
        mock_get.return_value = mock_policies
        mock_set.return_value = True

        result = self.security_manager.migrate_catalog_item_policies(
            "/source/item", "/target/item"
        )

        self.assertTrue(result)
        mock_get.assert_called_once_with("/source/item")
        mock_set.assert_called_once_with("/target/item", mock_policies)

    def test_get_folder_permissions_success(self):
        """Test de récupération des permissions de dossier"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "Policies": [
                {"GroupUserName": "DOMAIN\\user1", "Roles": ["Content Manager"]}
            ]
        }
        self.mock_client._make_request.return_value = mock_response
        self.mock_client._get_catalog_item_path.return_value = "/test/folder"

        result = self.security_manager.get_folder_permissions("/test/folder")

        self.assertIsNotNone(result)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["GroupUserName"], "DOMAIN\\user1")

    @patch.object(SSRSSecurityManager, "get_report_id")
    @patch.object(SSRSSecurityManager, "get_data_model_roles")
    @patch.object(SSRSSecurityManager, "get_data_model_role_assignments")
    @patch.object(SSRSSecurityManager, "set_data_model_role_assignments")
    def test_add_user_to_role_new_user(
        self, mock_set, mock_get_assignments, mock_get_roles, mock_get_id
    ):
        """Test d'ajout d'un nouvel utilisateur à un rôle"""
        mock_get_id.return_value = "report-id"
        mock_get_roles.return_value = {"Manager": "role-id-1"}
        mock_get_assignments.return_value = []
        mock_set.return_value = True

        result = self.security_manager.add_user_to_role(
            "/test/report", "DOMAIN\\newuser", ["Manager"]
        )

        self.assertTrue(result)

        # Vérifier que l'assignation a été créée
        call_args = mock_set.call_args[0]
        assignments = call_args[1]
        self.assertEqual(len(assignments), 1)
        self.assertEqual(assignments[0]["GroupUserName"], "DOMAIN\\newuser")
        self.assertEqual(assignments[0]["DataModelRoles"], ["role-id-1"])

    @patch.object(SSRSSecurityManager, "get_report_id")
    @patch.object(SSRSSecurityManager, "get_data_model_role_assignments")
    @patch.object(SSRSSecurityManager, "set_data_model_role_assignments")
    def test_remove_user_from_role_all_roles(
        self, mock_set, mock_get_assignments, mock_get_id
    ):
        """Test de suppression d'un utilisateur de tous les rôles"""
        mock_get_id.return_value = "report-id"
        mock_get_assignments.return_value = [
            {"GroupUserName": "DOMAIN\\user1", "DataModelRoles": ["role-id-1"]},
            {"GroupUserName": "DOMAIN\\user2", "DataModelRoles": ["role-id-2"]},
        ]
        mock_set.return_value = True

        result = self.security_manager.remove_user_from_role(
            "/test/report", "DOMAIN\\user1", None  # Retirer de tous les rôles
        )

        self.assertTrue(result)

        # Vérifier que seul user2 reste
        call_args = mock_set.call_args[0]
        assignments = call_args[1]
        self.assertEqual(len(assignments), 1)
        self.assertEqual(assignments[0]["GroupUserName"], "DOMAIN\\user2")

    @patch.object(SSRSSecurityManager, "get_report_id")
    @patch.object(SSRSSecurityManager, "get_data_model_roles")
    @patch.object(SSRSSecurityManager, "get_data_model_role_assignments")
    def test_list_role_assignments(
        self, mock_get_assignments, mock_get_roles, mock_get_id
    ):
        """Test de listage des assignations de rôles"""
        mock_get_id.return_value = "report-id"
        mock_get_roles.return_value = {"Manager": "role-id-1", "Employee": "role-id-2"}
        mock_get_assignments.return_value = [
            {"GroupUserName": "DOMAIN\\user1", "DataModelRoles": ["role-id-1"]},
            {
                "GroupUserName": "DOMAIN\\user2",
                "DataModelRoles": ["role-id-1", "role-id-2"],
            },
        ]

        result = self.security_manager.list_role_assignments("/test/report")

        expected = {
            "DOMAIN\\user1": ["Manager"],
            "DOMAIN\\user2": ["Manager", "Employee"],
        }
        self.assertEqual(result, expected)


class TestSecurityTypes(unittest.TestCase):
    """Test cases pour les types de sécurité"""

    def test_security_role_type_enum(self):
        """Test de l'énumération SecurityRoleType"""
        self.assertEqual(
            SecurityRoleType.SYSTEM_ADMINISTRATOR.value, "System Administrator"
        )
        self.assertEqual(SecurityRoleType.CONTENT_MANAGER.value, "Content Manager")
        self.assertEqual(SecurityRoleType.BROWSER.value, "Browser")

    def test_permission_type_enum(self):
        """Test de l'énumération PermissionType"""
        self.assertEqual(PermissionType.VIEW.value, "View")
        self.assertEqual(PermissionType.CREATE.value, "Create")
        self.assertEqual(PermissionType.MANAGE_SECURITY.value, "ManageSecurity")

    def test_rs_policy_creation(self):
        """Test de création d'une politique RsPolicy"""
        policy = RsPolicy(
            group_user_name="DOMAIN\\testuser",
            roles=["Browser", "Content Manager"],
            type="User",
        )

        self.assertEqual(policy.group_user_name, "DOMAIN\\testuser")
        self.assertEqual(policy.roles, ["Browser", "Content Manager"])
        self.assertEqual(policy.type, "User")

    def test_data_model_role_creation(self):
        """Test de création d'un rôle DataModelRole"""
        role = DataModelRole(
            model_role_id="role-123",
            model_role_name="Sales Manager",
            description="Sales manager role",
        )

        self.assertEqual(role.model_role_id, "role-123")
        self.assertEqual(role.model_role_name, "Sales Manager")
        self.assertEqual(role.description, "Sales manager role")

    def test_data_model_role_assignment_creation(self):
        """Test de création d'une assignation DataModelRoleAssignment"""
        assignment = DataModelRoleAssignment(
            group_user_name="DOMAIN\\user1",
            data_model_roles=["role-1", "role-2"],
            identity_type="User",
        )
        self.assertEqual(assignment.group_user_name, "DOMAIN\\user1")
        self.assertEqual(assignment.data_model_roles, ["role-1", "role-2"])
        self.assertEqual(assignment.identity_type, "User")


if __name__ == "__main__":
    # Create test suite
    test_suite = unittest.TestSuite()

    # Add test cases
    test_classes = [TestSSRSSecurityManager, TestSecurityTypes]

    for test_class in test_classes:
        tests = unittest.TestLoader().loadTestsFromTestCase(test_class)
        test_suite.addTests(tests)

    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(test_suite)

    # Exit with appropriate code
    exit(0 if result.wasSuccessful() else 1)
