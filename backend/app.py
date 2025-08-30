import json
from typing import Callable, Iterable, Any, Iterator
from mysql.connector.connection import MySQLConnection
import mysql.connector
import os
import urllib.parse
from contextlib import contextmanager

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

    data = {"message": f"Hello from backend/app.py! You are visiting {path}"}
    response_body: bytes = json.dumps(data).encode("utf-8")
    start_response("200 OK", [("Content-Type", "application/json")])
    return [response_body]

def signup(
        environ: WSGIEnvironment,
        start_response: StartResponse
) -> Iterable[bytes]:

    params = get_params(environ) # get params from post request
    username, password = params["username"], params["password"]

    
    data = {"message": f"Hello from signup! Username: {username}, Password: {password}"}
    response_body: bytes = json.dumps(data).encode("utf-8")
    start_response("200 OK", [("Content-Type", "application/json")])
    return [response_body]



