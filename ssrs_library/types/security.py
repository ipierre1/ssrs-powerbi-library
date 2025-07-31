from dataclasses import dataclass
from typing import List, Optional, Dict, Any
from enum import Enum


class SecurityRoleType(Enum):
    """SSRS Security Role Types"""

    SYSTEM_ADMINISTRATOR = "System Administrator"
    SYSTEM_USER = "System User"
    CONTENT_MANAGER = "Content Manager"
    PUBLISHER = "Publisher"
    BROWSER = "Browser"
    REPORT_BUILDER = "Report Builder"
    MY_REPORTS = "My Reports"


class PermissionType(Enum):
    """SSRS Permission Types"""

    VIEW = "View"
    CREATE = "Create"
    MODIFY = "Modify"
    DELETE = "Delete"
    MANAGE_SECURITY = "ManageSecurity"
    MANAGE_ROLES = "ManageRoles"
    VIEW_MODELS = "ViewModels"
    CREATE_MODELS = "CreateModels"


@dataclass
class RsPolicy:
    """Represents an SSRS Security Policy"""

    group_user_name: str
    roles: List[str]
    type: str = "User"  # "User" or "Group"


@dataclass
class RsSecurityDescriptor:
    """Represents an SSRS Security Descriptor"""

    policies: List[RsPolicy]
    inherit_parent_security: bool = True


@dataclass
class DataModelRole:
    """Represents a PowerBI Data Model Role"""

    model_role_id: str
    model_role_name: str
    description: Optional[str] = None


@dataclass
class DataModelRoleAssignment:
    """Represents a PowerBI Data Model Role Assignment"""

    group_user_name: str
    data_model_roles: List[str]  # List of role IDs
    identity_type: str = "User"  # "User" or "Group"


@dataclass
class RsPermission:
    """Represents an SSRS Permission"""

    permission_type: PermissionType
    granted: bool = True


@dataclass
class RsRoleAssignment:
    """Represents an SSRS Role Assignment"""

    group_user_name: str
    roles: List[str]
    permissions: List[RsPermission]
    type: str = "User"  # "User" or "Group"


@dataclass
class SecurityAuditEntry:
    """Represents a security audit entry"""

    item_path: str
    user_name: str
    action: str
    timestamp: str
    success: bool
    details: Optional[Dict[str, Any]] = None
