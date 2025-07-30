from enum import Enum


class RsItemType(Enum):
    FOLDER = "Folder"
    REPORT = "Report"
    DATA_SOURCE = "DataSource"
    DATA_SET = "DataSet"
    RESOURCE = "Resource"
    MOBILE_REPORT = "MobileReport"
    KPI = "Kpi"
    PAGINATED_REPORT = "PowerBIReport"
