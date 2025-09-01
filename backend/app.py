from typing import Iterable

from backend.lib.type_defs import WSGIEnvironment, StartResponse
from backend.lib.wsgiutils import serve_html
from backend.routes.signup import signup
from backend.routes.login import login
from backend.routes.dashboard import dashboard
from backend.routes.logout import logout


def application(
        environ: WSGIEnvironment, 
        start_response: StartResponse
) -> Iterable[bytes]:
    """
        Main entry point to the program
    """

    path: str = environ.get("PATH_INFO", "/")

    match path:
        case "/":
            return serve_html("../../frontend/index.html", start_response)
        case "/signup":
            return serve_html("../../frontend/signup.html", start_response)
        case "/login":
            return serve_html("../../frontend/login.html", start_response)
        case "/dashboard":
            return serve_html("../../frontend/dashboard.html", start_response)
        case "/api/signup":
            return signup(environ, start_response)
        case "/api/login":
            return login(environ, start_response)
        case "/api/dashboard":
            return dashboard(environ, start_response)
        case "/api/logout":
            return logout(environ, start_response)
        case _:
            start_response("404 Not Found", [("Content-Type", "text/plain")])
            return [b"File not found"]

