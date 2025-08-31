import json
from typing import Callable, Iterable, Any, Optional
from backend.app import exists_valid_session_id, get_session_id_from_cookies, redirect

WSGIEnvironment = dict[str, Any]
StartResponse = Callable[[str, list[tuple[str, str]]], None]
App = Callable[[WSGIEnvironment, StartResponse], Iterable[bytes]]

def auth_middleware(app: App) -> App:

    def wrapped_app(
        environ: WSGIEnvironment,
        start_response: StartResponse
    ) -> Iterable[bytes]:

        path: str = environ.get("PATH_INFO", "")

        # if path is not protected
        if path in ("/", "/signup", "/api/signup", "/login", "/api/login"):
            return app(environ, start_response)

        # get session id
        session_id: Optional[str] = get_session_id_from_cookies(environ)

        # if session exists and is valid
        if session_id is not None and exists_valid_session_id(session_id):
            return app(environ, start_response)

        # unauthorized to access protected /api route
        if path.startswith("/api"):
            start_response(
                "401 Unauthorized",
                [("Content-Type", "application/json")]
            )
            data = {"error": "Unauthorized"}
            response_body: bytes = json.dumps(data).encode("utf-8")
            return [response_body]

        # redirect to login
        else:
            return redirect(start_response, "/login")

    return wrapped_app

