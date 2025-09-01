from typing import Any, Optional
import sys
import bcrypt
from datetime import datetime, timedelta

from backend.lib.type_defs import WSGIEnvironment
from backend.lib.db import get_db


def hash_password(password: str) -> str:
    """
        Function to hash a password string
    """
    encoded = password.encode("utf-8")
    hashed = bcrypt.hashpw(encoded, bcrypt.gensalt())
    return hashed.decode()


def check_passwords(hash_row: Optional[dict[str, str]], input_pw):
    """
        Function to check if an input password matches the user's
        stored password hash if it exists
    """
    if hash_row is None:
        return False # user doesn't exist
    else:
        stored_hash_bytes = hash_row["password_hash"].encode("utf-8")
        return bcrypt.checkpw(input_pw.encode("utf-8"), stored_hash_bytes)


def is_session_valid(create_time: datetime) -> bool:
    """
        Checks if the session id is not expired given its create time
    """
    return datetime.now() - create_time <= timedelta(minutes=1)
    

def validate_session_id(
        session_row: Optional[dict[str, Any]], 
        existing_session: Optional[str]
) -> Optional[str]:
    """
        Checks if a session id is valid and returns it if it is
        Returns None otherwise
    """

    if session_row is None or existing_session is None:
        return None

    session_id = session_row["id"]
    create_time: datetime = session_row["created_at"]
    return session_id if is_session_valid(create_time) else None


def exists_valid_session_id(session_id: str) -> bool:
    """
        Checks if a user's session id is valid and exists
    """
    with get_db() as conn:
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            """
                SELECT id, created_at FROM sessions
                WHERE id = %s
            """,
            (session_id,)
        )
        session_row: Optional[dict[str, Any]] = cursor.fetchone()
        cursor.close()
    validated: Optional[str] = validate_session_id(session_row, session_id)
    return validated is not None


def get_session_id_from_cookies(environ: WSGIEnvironment) -> Optional[str]:
    """
        Gets the session id from the environ's cookies
        Returns None if doesn't exist
    """
    cookies = environ.get("HTTP_COOKIE", "")
    session_id = None
    for cookie in cookies.split(";"):
        # .partition splits on the first = which is safer than .split
        key, _, value = cookie.strip().partition("=")
        if key == "session_id":
            session_id = value
            break
    return session_id
