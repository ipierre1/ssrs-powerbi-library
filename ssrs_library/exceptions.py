class PBIRSError(Exception):
    """Base exception for PBIRS API errors."""

    def __init__(self, message, status_code=None):
        super().__init__(message)
        self.status_code = status_code


class PBIRSNotFound(PBIRSError):
    """Raised when a resource is not found (HTTP 404)."""
    pass


class PBIRSConflict(PBIRSError):
    """Raised on a naming conflict (HTTP 409)."""
    pass


class PBIRSAuthError(PBIRSError):
    """Raised when authentication or authorization fails (HTTP 401/403)."""
    pass
