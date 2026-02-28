"""
Shared slowapi Limiter instance.

Import `limiter` from here in routers that need rate-limit decorators.
The limiter is wired into the FastAPI app in backend/main.py.

Usage in a router:
    from fastapi import Request
    from ..ratelimit import limiter

    @router.get("/path")
    @limiter.limit("60/minute")
    def my_endpoint(request: Request, ...):
        ...

Note: slowapi requires `request: Request` to be a parameter on any
decorated route function — it reads the client IP from it.
"""
from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)
