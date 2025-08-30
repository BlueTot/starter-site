import sys
import json
from typing import Callable, Iterable, Any, Iterator, Optional
from mysql.connector.connection import MySQLConnection
import mysql.connector
import os
import urllib.parse
from contextlib import contextmanager
import bcrypt
import uuid
from datetime import datetime, timedelta, timezone

WSGIEnvironment = dict[str, Any]
StartResponse = Callable[[str, list[tuple[str, str]]], None]

@contextmanager
def get_db() -> Iterator[MySQLConnection]:
    """
        A context manager for the MySQL database connection
    """
    conn =  mysql.connector.connect(
        host=os.getenv("DB_HOST"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
        database=os.getenv("DB_NAME")
    )
    try:
        yield conn # type: ignore[return-value]
    finally:
        conn.close()


def get_params(environ: WSGIEnvironment) -> dict[str, str]:
    """
        Function to get the params from a POST request
    """
    return dict(urllib.parse.parse_qsl(
        environ['wsgi.input'].read(int(environ['CONTENT_LENGTH'])).decode())
    )


def hash_password(password: str) -> str:
    """
        Function to hash a password string
    """
    encoded = password.encode("utf-8")
    hashed = bcrypt.hashpw(encoded, bcrypt.gensalt())
    return hashed.decode()


def redirect(start_response: StartResponse, location: str):
    """
        Function to redirect user to given route
        Returns a response
    """
    start_response("302 Found", [
        ("Location", location),
        ("Content-Type", "text/plain")
    ])
    return [b"Redirecting..."]


def application(
        environ: WSGIEnvironment, 
        start_response: StartResponse
) -> Iterable[bytes]:
    """
        Main entry point to the program
    """

    path: str = environ.get("PATH_INFO", "/")

    if path == "/signup":
        return signup(environ, start_response)
    elif path == "/login":
        return login(environ, start_response)

    data = {"message": f"Hello from backend/app.py! You are visiting {path}"}
    response_body: bytes = json.dumps(data).encode("utf-8")
    start_response("200 OK", [("Content-Type", "application/json")])
    return [response_body]

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

"""

CREATE TABLE users (
    id CHAR(36) PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE SESSIONS (
    id CHAR(36) PRIMARY KEY,
    user_id CHAR(36) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);
"""

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

    session_id = session_row ["id"]
    create_time: datetime = session_row["created_at"]
    if datetime.now() - create_time <= timedelta(minutes=1):
        return session_id
    else:
        return None


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
        
    cookies = environ.get("HTTP_COOKIE", "")
    session_id = None
    for cookie in cookies.split(";"):
        key, _, value = cookie.strip().partition("=")
        if key == "session_id":
            session_id = value
            break

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
        session_row = cursor.fetchone()
        cursor.close()

    validated_session = validate_session_id(session_row, session_id)

    print(validated_session, file=sys.stderr)

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
        ("Location", "/dashboard.html"),
        ("Set-Cookie", f"session_id={new_session_id}; HttpOnly; Path=/"),
    ])
    return [b"Logging in..."]

