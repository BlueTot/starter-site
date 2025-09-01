import json
from typing import Iterable, Optional

from backend.lib.type_defs import WSGIEnvironment, StartResponse
from backend.lib.db import get_db
from backend.lib.auth import get_session_id_from_cookies


def dashboard(
        environ: WSGIEnvironment,
        start_response: StartResponse
) -> Iterable[bytes]:
    """
        Function to get the username given the user's valid session id
        (Protected Route)
    """
    
    session_id: Optional[str] = get_session_id_from_cookies(environ)
    if session_id is None:
        raise Exception("Accessing dashboard with no session id???")

    with get_db() as conn:
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            """
                SELECT username FROM users
                INNER JOIN sessions ON users.id = sessions.user_id
                WHERE sessions.id = %s
            """,
            (session_id,)
        )
        # ignore type warning as we will always have a username
        username: str = cursor.fetchone()["username"] # type: ignore
        cursor.close()
    
    data = {"username": username}
    response_body: bytes = json.dumps(data).encode("utf-8")
    start_response("200 OK", [("Content-Type", "application/json")])
    return [response_body]

