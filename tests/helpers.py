"""Shared test helpers."""
from unittest.mock import Mock
import requests


def make_response(status: int, body=None):
    """
    Build a fake requests.Response for a given HTTP status code.

    :param status: HTTP status code (e.g. 200, 204, 404).
    :param body:   Dict that will be returned by ``.json()``.
                   Pass ``None`` to simulate an empty body (204-style).
    """
    r = Mock()
    r.status_code = status
    r.content = b"data" if body is not None else b""
    r.headers = {"Content-Type": "application/json"}
    r.json.return_value = body
    if status >= 400:
        r.raise_for_status.side_effect = requests.HTTPError(
            f"HTTP {status}", response=r
        )
    else:
        r.raise_for_status.return_value = None
    return r
