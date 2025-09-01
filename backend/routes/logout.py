from typing import Iterable, Optional

from backend.lib.type_defs import WSGIEnvironment, StartResponse
from backend.lib.db import get_db
from backend.lib.auth import get_session_id_from_cookies
from backend.lib.wsgiutils import redirect


def logout(
        environ: WSGIEnvironment,
        start_response: StartResponse
) -> Iterable[bytes]:
    """
        Function that logs out the current user's session
        (Protected Route)
    """

    session_id: Optional[str] = get_session_id_from_cookies(environ)
    if session_id is None:
        raise Exception("Accessing logout with no session id???")

    # delete cookie in sessions table
    with get_db() as conn:
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            """
                DELETE FROM sessions
                WHERE sessions.id = %s
            """,
            (session_id,)
        )
        conn.commit()
        cursor.close()

    # redirect to / and clear cookie
    return redirect(
        start_response, "/",
        ("Set-Cookie", "session_id=; Path=/; Max-Age=0; HttpOnly; Secure")
    )

