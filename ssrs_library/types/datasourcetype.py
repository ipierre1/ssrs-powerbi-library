from enum import Enum


class DataSourceType(Enum):
    SQL = "SQL"
    OLEDB = "OLEDB"
    ODBC = "ODBC"
    ORACLE = "Oracle"
    XML = "XML"
    WEB = "Web"
    SHAREPOINT_LIST = "SharePointList"
