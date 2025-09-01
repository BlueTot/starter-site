import json
from typing import Iterable, Any, Optional
import uuid
from datetime import datetime, timezone

from backend.lib.type_defs import WSGIEnvironment, StartResponse
from backend.lib.db import get_db
from backend.lib.auth import check_passwords, get_session_id_from_cookies, validate_session_id
from backend.lib.wsgiutils import get_params


def login(
        environ: WSGIEnvironment,
        start_response: StartResponse
) -> Iterable[bytes]:
    """
        Login route
    """

    params = get_params(environ)
    username, password = params["username"], params["password"]

    # check if username exists and password is correct
    with get_db() as conn:
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            "SELECT password_hash FROM users WHERE username = %s",
            (username,)
        )
        hash_row = cursor.fetchone()
        cursor.close()

    if not check_passwords(hash_row, password):
        data = {"message": "Invalid username or password"}
        response_body: bytes = json.dumps(data).encode("utf-8")
        start_response("401 Unauthorized", [("Content-Type", "application/json")])
        return [response_body]

    # check if existing session is valid
    # if is valid, we set the cookie as usual
    # otherwise, we generate a new session id and set the cookie

    session_id: Optional[str] = get_session_id_from_cookies(environ)

    # find stored session data
    with get_db() as conn:
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            """
                SELECT sessions.id, sessions.created_at FROM sessions
                INNER JOIN users ON users.id = sessions.user_id
                WHERE username = %s
            """,
            (username,)
        )
        session_row: Optional[dict[str, Any]] = cursor.fetchone()
        cursor.close()

    validated_session = validate_session_id(session_row, session_id)

    # print(validated_session, file=sys.stderr)

    # invalid session id
    if validated_session is None:

        new_session_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc)

        # store session data
        with get_db() as conn:
            cursor = conn.cursor(dictionary=True)
            
            # no previous session exists - insert
            if session_row is None:
                cursor.execute(
                    """
                        INSERT INTO sessions (id, user_id) 
                        SELECT %s, users.id
                        FROM users
                        WHERE users.username = %s
                    """,
                    (new_session_id, username)
                )
            # previous session exists - update it
            else:
                cursor.execute(
                    """
                        UPDATE sessions 
                        INNER JOIN users ON users.id = sessions.user_id
                        SET sessions.id = %s, sessions.created_at = %s
                        WHERE username = %s
                    """,
                    (new_session_id, now, username)
                )
            conn.commit()
            cursor.close()
    else:
        new_session_id = validated_session

    # set cookie and send response
    start_response("303 See Other", [
        ("Location", "/dashboard"),
        ("Set-Cookie", f"session_id={new_session_id}; HttpOnly; Path=/"),
    ])
    return [b"Logging in..."]
