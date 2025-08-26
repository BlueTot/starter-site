import json

def application(environ, start_response):
    path = environ.get("PATH_INFO", "/")

    data = {"message": f"Hello from backend/app.py! You are visiting {path}"}
    response_body = json.dumps(data).encode("utf-8")
    start_response("200 OK", [("Content-Type", "application/json")])
    return [response_body]
