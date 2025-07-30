from dataclasses import dataclass
from typing import Optional

@dataclass
class RsCredentials:
    pass

@dataclass
class CredentialsByUser(RsCredentials):
    username: str
    password: str
    domain: Optional[str] = None

@dataclass
class CredentialsInServer(RsCredentials):
    username: str
    password: str
    domain: Optional[str] = None
    windows_credentials: bool = True

@dataclass
class NoCredentials(RsCredentials):
    pass
