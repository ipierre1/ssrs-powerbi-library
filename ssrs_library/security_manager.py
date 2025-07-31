import requests
import logging
from typing import List, Dict, Optional, Any, Union

from .types.rsitem import RsItem
from .types.rsitemtype import RsItemType
from .types.security import (
    SecurityRoleType,
    PermissionType,
    RsPolicy,
    RsSecurityDescriptor,
    DataModelRole,
    DataModelRoleAssignment,
    RsPermission,
    RsRoleAssignment,
    SecurityAuditEntry
)


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class SSRSSecurityManager:
    """
    Manager class for SSRS Security operations (RLS, Policies, Permissions)
    """

    def __init__(self, client):
        # Import here to avoid circular import
        from .ssrs_library import SSRSRestClient

        if not isinstance(client, SSRSRestClient):
            raise TypeError("client must be an instance of SSRSRestClient")

        self.client = client

    def get_report_id(self, report_path: str) -> Optional[str]:
        """
        Get report ID from report path

        Args:
            report_path: Full path to the report

        Returns:
            Report ID if found, None otherwise
        """
        try:
            report_name_simple = report_path.split("/")[-1]
            # Use a specific folder ID or search in all folders
            catalog_items_url = f"Folders(a09ce8a9-8390-4651-9127-d6007e7b29d4)/Model.SearchItems(searchText='{report_name_simple}')"

            response = self.client._make_request("GET", catalog_items_url)

            if response.status_code == 200:
                items = response.json().get("value", [])
                for item in items:
                    if item["Path"] == report_path:
                        return item["Id"]

                logger.warning(f"Report '{report_path}' not found")
                return None
            else:
                logger.error(
                    f"Failed to retrieve catalog items. Status code: {response.status_code}"
                )
                return None

        except requests.RequestException as e:
            logger.error(f"Failed to get report ID for {report_path}: {str(e)}")
            return None

    def get_data_model_roles(self, report_id: str) -> Dict[str, str]:
        """
        Get data model roles for a PowerBI report

        Args:
            report_id: Report ID

        Returns:
            Dictionary mapping role names to role IDs
        """
        try:
            roles_url = f"PowerBIReports({report_id})/DataModelRoles"
            response = self.client._make_request("GET", roles_url)

            if response.status_code == 200:
                roles = response.json().get("value", [])
                return {role["ModelRoleName"]: role["ModelRoleId"] for role in roles}
            else:
                logger.error(
                    f"Failed to retrieve DataModelRoles. Status code: {response.status_code}"
                )
                return {}

        except requests.RequestException as e:
            logger.error(
                f"Failed to get data model roles for report {report_id}: {str(e)}"
            )
            return {}

    def get_data_model_role_assignments(self, report_id: str) -> List[Dict[str, Any]]:
        """
        Get data model role assignments for a PowerBI report

        Args:
            report_id: Report ID

        Returns:
            List of role assignments
        """
        try:
            assignments_url = f"PowerBIReports({report_id})/DataModelRoleAssignments"
            response = self.client._make_request("GET", assignments_url)

            if response.status_code == 200:
                return response.json().get("value", [])
            else:
                logger.error(
                    f"Failed to retrieve DataModelRoleAssignments. Status code: {response.status_code}"
                )
                return []

        except requests.RequestException as e:
            logger.error(
                f"Failed to get data model role assignments for report {report_id}: {str(e)}"
            )
            return []

    def set_data_model_role_assignments(
        self, report_id: str, assignments: List[Dict[str, Any]]
    ) -> bool:
        """
        Set data model role assignments for a PowerBI report

        Args:
            report_id: Report ID
            assignments: List of role assignments

        Returns:
            True if successful, False otherwise
        """
        try:
            assignments_url = f"PowerBIReports({report_id})/DataModelRoleAssignments"

            response = self.client._make_request(
                "PUT", assignments_url, json=assignments
            )

            if response.status_code == 200:
                logger.info("DataModelRoleAssignments updated successfully.")
                return True
            else:
                logger.error(
                    f"Failed to update DataModelRoleAssignments. Status code: {response.status_code}"
                )
                logger.error(response.text)
                return False

        except requests.RequestException as e:
            logger.error(
                f"Failed to set data model role assignments for report {report_id}: {str(e)}"
            )
            return False

    def create_role_mapping(
        self, roles_source: Dict[str, str], roles_target: Dict[str, str]
    ) -> Dict[str, str]:
        """
        Create a mapping from source role IDs to target role IDs based on role names

        Args:
            roles_source: Source roles (name -> ID mapping)
            roles_target: Target roles (name -> ID mapping)

        Returns:
            Dictionary mapping source role IDs to target role IDs
        """
        role_mapping = {}

        for role_name, source_role_id in roles_source.items():
            if role_name in roles_target:
                role_mapping[source_role_id] = roles_target[role_name]
            else:
                logger.warning(f"Role '{role_name}' not found in target")

        return role_mapping

    def migrate_data_model_role_assignments(
        self, source_report_path: str, target_report_path: str
    ) -> bool:
        """
        Migrate data model role assignments from source report to target report

        Args:
            source_report_path: Path to source report
            target_report_path: Path to target report

        Returns:
            True if successful, False otherwise
        """
        try:
            # Get report IDs
            source_report_id = self.get_report_id(source_report_path)
            target_report_id = self.get_report_id(target_report_path)

            if not source_report_id or not target_report_id:
                logger.error("Could not retrieve one or both report IDs")
                return False

            # Get roles from both reports
            source_roles = self.get_data_model_roles(source_report_id)
            target_roles = self.get_data_model_roles(target_report_id)

            # Create role mapping
            role_mapping = self.create_role_mapping(source_roles, target_roles)

            # Get assignments from source
            source_assignments = self.get_data_model_role_assignments(source_report_id)

            # Map assignments using the role mapping
            mapped_assignments = []
            for assignment in source_assignments:
                role_ids_source = assignment.get("DataModelRoles", [])
                mapped_roles = []

                for source_role_id in role_ids_source:
                    if source_role_id in role_mapping:
                        mapped_roles.append(role_mapping[source_role_id])
                    else:
                        logger.warning(
                            f"Role ID '{source_role_id}' from source not mapped to target"
                        )

                if mapped_roles:  # Only add assignment if we have mapped roles
                    mapped_assignment = {
                        "GroupUserName": assignment.get("GroupUserName"),
                        "DataModelRoles": mapped_roles,
                    }
                    mapped_assignments.append(mapped_assignment)

            # Set assignments on target
            return self.set_data_model_role_assignments(
                target_report_id, mapped_assignments
            )

        except Exception as e:
            logger.error(
                f"Failed to migrate role assignments from {source_report_path} to {target_report_path}: {str(e)}"
            )
            return False

    def get_catalog_item_policies(self, item_path: str) -> Optional[Dict[str, Any]]:
        """
        Get security policies for a catalog item

        Args:
            item_path: Path to the catalog item

        Returns:
            Policies dictionary if successful, None otherwise
        """
        try:
            item = self.client.get_catalog_item(item_path)
            policies_url = f"CatalogItems({item.id})/Policies"

            response = self.client._make_request("GET", policies_url)

            if response.status_code == 200:
                logger.info(f"Policies retrieved from {item_path}")
                return response.json()
            else:
                logger.error(
                    f"Failed to retrieve Policies. Status code: {response.status_code}"
                )
                return None

        except Exception as e:
            logger.error(f"Failed to get policies for {item_path}: {str(e)}")
            return None

    def set_catalog_item_policies(
        self, item_path: str, policies: Dict[str, Any]
    ) -> bool:
        """
        Set security policies for a catalog item

        Args:
            item_path: Path to the catalog item
            policies: Policies dictionary

        Returns:
            True if successful, False otherwise
        """
        try:
            item = self.client.get_catalog_item(item_path)
            policies_url = f"CatalogItems({item.id})/Policies"

            # Remove metadata fields that shouldn't be sent back
            clean_policies = policies.copy()
            clean_policies.pop("@odata.context", None)
            clean_policies.pop("Id", None)

            response = self.client._make_request(
                "PUT", policies_url, json=clean_policies
            )

            if response.status_code == 200:
                logger.info(f"Policies updated successfully on {item_path}")
                return True
            else:
                logger.error(
                    f"Failed to update policies. Status code: {response.status_code}"
                )
                logger.error(response.text)
                return False

        except Exception as e:
            logger.error(f"Failed to set policies for {item_path}: {str(e)}")
            return False

    def migrate_catalog_item_policies(self, source_path: str, target_path: str) -> bool:
        """
        Migrate security policies from source catalog item to target catalog item

        Args:
            source_path: Path to source catalog item
            target_path: Path to target catalog item

        Returns:
            True if successful, False otherwise
        """
        try:
            # Get policies from source
            source_policies = self.get_catalog_item_policies(source_path)

            if not source_policies:
                logger.warning(f"No policies found for source item: {source_path}")
                return False

            # Set policies on target
            return self.set_catalog_item_policies(target_path, source_policies)

        except Exception as e:
            logger.error(
                f"Failed to migrate policies from {source_path} to {target_path}: {str(e)}"
            )
            return False

    def get_folder_permissions(
        self, folder_path: str
    ) -> Optional[List[Dict[str, Any]]]:
        """
        Get permissions for a folder

        Args:
            folder_path: Path to the folder

        Returns:
            List of permissions if successful, None otherwise
        """
        try:
            formatted_path = self.client._get_catalog_item_path(folder_path)
            permissions_url = f"Folders(Path='{formatted_path}')/Policies"

            response = self.client._make_request("GET", permissions_url)

            if response.status_code == 200:
                policies = response.json()
                return policies.get("Policies", [])
            else:
                logger.error(
                    f"Failed to retrieve folder permissions. Status code: {response.status_code}"
                )
                return None

        except Exception as e:
            logger.error(
                f"Failed to get folder permissions for {folder_path}: {str(e)}"
            )
            return None

    def set_folder_permissions(
        self, folder_path: str, permissions: List[Dict[str, Any]]
    ) -> bool:
        """
        Set permissions for a folder

        Args:
            folder_path: Path to the folder
            permissions: List of permission objects

        Returns:
            True if successful, False otherwise
        """
        try:
            formatted_path = self.client._get_catalog_item_path(folder_path)
            permissions_url = f"Folders(Path='{formatted_path}')/Policies"

            policies_payload = {"Policies": permissions}

            response = self.client._make_request(
                "PUT", permissions_url, json=policies_payload
            )

            if response.status_code == 200:
                logger.info(
                    f"Folder permissions updated successfully for {folder_path}"
                )
                return True
            else:
                logger.error(
                    f"Failed to update folder permissions. Status code: {response.status_code}"
                )
                logger.error(response.text)
                return False

        except Exception as e:
            logger.error(
                f"Failed to set folder permissions for {folder_path}: {str(e)}"
            )
            return False

    def copy_folder_permissions(self, source_folder: str, target_folder: str) -> bool:
        """
        Copy permissions from source folder to target folder

        Args:
            source_folder: Path to source folder
            target_folder: Path to target folder

        Returns:
            True if successful, False otherwise
        """
        try:
            # Get permissions from source folder
            source_permissions = self.get_folder_permissions(source_folder)

            if not source_permissions:
                logger.warning(
                    f"No permissions found for source folder: {source_folder}"
                )
                return False

            # Set permissions on target folder
            return self.set_folder_permissions(target_folder, source_permissions)

        except Exception as e:
            logger.error(
                f"Failed to copy folder permissions from {source_folder} to {target_folder}: {str(e)}"
            )
            return False

    def add_user_to_role(
        self, report_path: str, username: str, role_names: List[str]
    ) -> bool:
        """
        Add a user to specific roles in a PowerBI report

        Args:
            report_path: Path to the PowerBI report
            username: Username to add
            role_names: List of role names to assign

        Returns:
            True if successful, False otherwise
        """
        try:
            report_id = self.get_report_id(report_path)
            if not report_id:
                return False

            # Get current roles and assignments
            roles = self.get_data_model_roles(report_id)
            current_assignments = self.get_data_model_role_assignments(report_id)

            # Find role IDs for the specified role names
            role_ids = []
            for role_name in role_names:
                if role_name in roles:
                    role_ids.append(roles[role_name])
                else:
                    logger.warning(
                        f"Role '{role_name}' not found in report {report_path}"
                    )

            if not role_ids:
                logger.error("No valid roles found")
                return False

            # Check if user already exists in assignments
            user_assignment = None
            for assignment in current_assignments:
                if assignment.get("GroupUserName") == username:
                    user_assignment = assignment
                    break

            if user_assignment:
                # Update existing assignment
                existing_roles = set(user_assignment.get("DataModelRoles", []))
                existing_roles.update(role_ids)
                user_assignment["DataModelRoles"] = list(existing_roles)
            else:
                # Add new assignment
                new_assignment = {"GroupUserName": username, "DataModelRoles": role_ids}
                current_assignments.append(new_assignment)

            # Update assignments
            return self.set_data_model_role_assignments(report_id, current_assignments)

        except Exception as e:
            logger.error(
                f"Failed to add user {username} to roles in {report_path}: {str(e)}"
            )
            return False

    def remove_user_from_role(
        self, report_path: str, username: str, role_names: List[str] = None
    ) -> bool:
        """
        Remove a user from specific roles or all roles in a PowerBI report

        Args:
            report_path: Path to the PowerBI report
            username: Username to remove
            role_names: List of role names to remove from (None = remove from all roles)

        Returns:
            True if successful, False otherwise
        """
        try:
            report_id = self.get_report_id(report_path)
            if not report_id:
                return False

            # Get current assignments
            current_assignments = self.get_data_model_role_assignments(report_id)

            # Find user assignment
            updated_assignments = []
            user_found = False

            for assignment in current_assignments:
                if assignment.get("GroupUserName") == username:
                    user_found = True

                    if role_names is None:
                        # Remove user completely
                        continue
                    else:
                        # Remove from specific roles
                        roles = self.get_data_model_roles(report_id)
                        role_ids_to_remove = [
                            roles[name] for name in role_names if name in roles
                        ]

                        current_role_ids = set(assignment.get("DataModelRoles", []))
                        updated_role_ids = current_role_ids - set(role_ids_to_remove)

                        if updated_role_ids:
                            assignment["DataModelRoles"] = list(updated_role_ids)
                            updated_assignments.append(assignment)
                        # If no roles left, user is removed (assignment not added)
                else:
                    updated_assignments.append(assignment)

            if not user_found:
                logger.warning(
                    f"User {username} not found in role assignments for {report_path}"
                )
                return True  # Not an error if user wasn't assigned

            # Update assignments
            return self.set_data_model_role_assignments(report_id, updated_assignments)

        except Exception as e:
            logger.error(
                f"Failed to remove user {username} from roles in {report_path}: {str(e)}"
            )
            return False

    def list_role_assignments(self, report_path: str) -> Dict[str, List[str]]:
        """
        List all role assignments for a PowerBI report

        Args:
            report_path: Path to the PowerBI report

        Returns:
            Dictionary mapping usernames to list of role names
        """
        try:
            report_id = self.get_report_id(report_path)
            if not report_id:
                return {}

            # Get roles and assignments
            roles = self.get_data_model_roles(report_id)
            assignments = self.get_data_model_role_assignments(report_id)

            # Create reverse mapping (role ID -> role name)
            role_id_to_name = {v: k for k, v in roles.items()}

            # Build user assignments
            user_assignments = {}
            for assignment in assignments:
                username = assignment.get("GroupUserName")
                role_ids = assignment.get("DataModelRoles", [])

                role_names = [
                    role_id_to_name.get(role_id, f"Unknown({role_id})")
                    for role_id in role_ids
                ]
                user_assignments[username] = role_names

            return user_assignments

        except Exception as e:
            logger.error(f"Failed to list role assignments for {report_path}: {str(e)}")
            return {}
