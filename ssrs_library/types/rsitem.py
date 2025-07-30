from dataclasses import dataclass
from typing import Optional
from .rsitemtype import RsItemType

@dataclass
class RsItem:
    name: str
    path: str
    item_type: RsItemType
    id: Optional[str] = None
    description: Optional[str] = None
    hidden: bool = False
    size: Optional[int] = None
    created_date: Optional[str] = None
    modified_date: Optional[str] = None
    created_by: Optional[str] = None
    modified_by: Optional[str] = None
