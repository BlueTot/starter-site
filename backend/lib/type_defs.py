from typing import Callable, Iterable, Any

WSGIEnvironment = dict[str, Any]
StartResponse = Callable[[str, list[tuple[str, str]]], None]
App = Callable[[WSGIEnvironment, StartResponse], Iterable[bytes]]
