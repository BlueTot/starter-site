import os
from typing import Iterable, Optional
import urllib.parse

from backend.lib.type_defs import WSGIEnvironment, StartResponse


def get_params(environ: WSGIEnvironment) -> dict[str, str]:
    """
        Function to get the params from a POST request
    """
    return dict(urllib.parse.parse_qsl(
        environ['wsgi.input'].read(int(environ['CONTENT_LENGTH'])).decode())
    )


def redirect(
        start_response: StartResponse, 
        location: str, 
        set_cookie: Optional[tuple[str, str]] = None
) -> Iterable[bytes]:
    """
        Function to redirect user to given route
        Returns a response
    """
    headers = [
        ("Location", location),
        ("Content-Type", "text/plain")
    ]
    if set_cookie is not None:
        headers.append(set_cookie)
    start_response("302 Found", headers)
    return [b"Redirecting..."]


def serve_html(filename: str, start_response):
    """
        Function to serve frontend html to the browser
        For frontend routes
    """
    filepath = os.path.join(os.path.dirname(__file__), filename)

    if not os.path.exists(filepath):
        start_response("404 Not Found", [("Content-Type", "text/plain")])
        return [b"File not found"]
    
    with open(filepath, "rb") as f:
        content = f.read()

    start_response("200 OK", [("Content-Type", "text/html")])
    return [content]
