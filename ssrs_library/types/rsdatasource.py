from dataclasses import dataclass
from typing import Optional, Any
from .rscredentials import RsCredentials


@dataclass
class RsDataSource:
    name: str
    data_source_type: str
    connection_string: str
    credentials: Optional[RsCredentials] = None
    enabled: bool = True
    path: Optional[str] = None
    id: Optional[str] = None
    description: Optional[str] = None
    data_source_sub_type: Optional[str] = None
    credential_retrieval: Optional[str] = None
    credentials_by_user: Optional[str] = None
    credentials_in_server: Optional[str] = None
    data_model_data_source: Optional[Any] = None
