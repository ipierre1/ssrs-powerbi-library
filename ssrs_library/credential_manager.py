# ssrs_library/credential_manager.py
from .types.rscredentials import CredentialsByUser, CredentialsInServer, NoCredentials


def create_credentials_by_user(
    username: str, password: str, domain: str = None
) -> CredentialsByUser:
    """
    Create CredentialsByUser object

    Args:
        username: Username
        password: Password
        domain: Domain (optional)

    Returns:
        CredentialsByUser object
    """
    return CredentialsByUser(username=username, password=password, domain=domain)


def create_credentials_in_server(
    username: str, password: str, domain: str = None, windows_credentials: bool = True
) -> CredentialsInServer:
    """
    Create CredentialsInServer object

    Args:
        username: Username
        password: Password
        domain: Domain (optional)
        windows_credentials: Whether to use Windows credentials

    Returns:
        CredentialsInServer object
    """
    return CredentialsInServer(
        username=username,
        password=password,
        domain=domain,
        windows_credentials=windows_credentials,
    )


def create_no_credentials() -> NoCredentials:
    """
    Create NoCredentials object

    Returns:
        NoCredentials object
    """
    return NoCredentials()
