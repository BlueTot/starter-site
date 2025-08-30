import json
from typing import Callable, Iterable, Any, Iterator
from mysql.connector.connection import MySQLConnection
import mysql.connector
import os
import urllib.parse
from contextlib import contextmanager
import bcrypt
import uuid

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


def login(
        environ: WSGIEnvironment,
        start_response: StartResponse
) -> Iterable[bytes]:
    """
        Login route
    """

    params = get_params(environ)
    username, password = params["username"], params["password"]

    data = {"message": f"Hello from /login, username: {username}, password: {password}"}
    response_body: bytes = json.dumps(data).encode("utf-8")
    start_response("200 OK", [("Content-Type", "application/json")])
    return [response_body]


