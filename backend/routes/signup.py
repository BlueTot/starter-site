import json
from typing import Iterable
import uuid

from backend.lib.type_defs import WSGIEnvironment, StartResponse
from backend.lib.db import get_db
from backend.lib.auth import hash_password
from backend.lib.wsgiutils import get_params, redirect

def signup(
        environ: WSGIEnvironment,
        start_response: StartResponse
) -> Iterable[bytes]:
    """
        Signup route
    """

    params = get_params(environ) # get params from post request
    username, password = params["username"], params["password"]

    # check if username exists already
    with get_db() as conn:
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            "SELECT username FROM users WHERE username = %s",
            (username,)
        )
        existing_users = cursor.fetchall()
        cursor.close() # close the cursor

    # if the username already exists
    if existing_users:
        data = {"message": f"Username {username} already exists"}
        response_body: bytes = json.dumps(data).encode("utf-8")
        start_response("409 Conflict", [("Content-Type", "application/json")])
        return [response_body]

    # otherwise, create a new user

    user_id = str(uuid.uuid4())
    hashed = hash_password(password) # hash the password

    with get_db() as conn:
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            """
                INSERT INTO users (id, username, password_hash)
                VALUES (%s, %s, %s)
            """,
            (user_id, username, hashed)
        )
        conn.commit() # push changes
        cursor.close() # close the cursor
    
    return redirect(start_response, "/")

