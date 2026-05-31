"""Clerk JWT authentication for FastAPI.

Verifies Clerk session tokens (JWTs) using the JWKS endpoint.
When CLERK_ISSUER is not configured, auth is disabled for local dev.
"""

import logging

import jwt
from jwt import PyJWKClient
from fastapi import HTTPException
from starlette.requests import HTTPConnection

from app.config import settings

logger = logging.getLogger(__name__)

_jwks_client: PyJWKClient | None = None


def _get_jwks_client() -> PyJWKClient | None:
    global _jwks_client
    if _jwks_client is None and settings.CLERK_ISSUER:
        _jwks_client = PyJWKClient(
            f"{settings.CLERK_ISSUER}/.well-known/jwks.json",
            cache_keys=True,
        )
    return _jwks_client


async def get_current_user(conn: HTTPConnection) -> dict:
    """Require authentication and return user info from the Clerk JWT.

    Works for both HTTP requests (Authorization header) and WebSocket
    connections (token query param or Authorization header).
    When CLERK_ISSUER is not set, returns an anonymous user so local dev
    works without Clerk configuration.
    """
    if not settings.CLERK_ISSUER:
        return {"user_id": "local", "email": None}

    auth_header = conn.headers.get("Authorization", "")
    # WebSocket clients can't set headers easily — accept token query param too
    if not auth_header.startswith("Bearer ") and "token" in conn.query_params:
        auth_header = f"Bearer {conn.query_params['token']}"
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Authentication required")

    token = auth_header[7:]
    client = _get_jwks_client()
    if client is None:
        raise HTTPException(status_code=500, detail="Auth not configured")

    try:
        signing_key = client.get_signing_key_from_jwt(token)
        decode_options = {
            "algorithms": ["RS256"],
            "issuer": settings.CLERK_ISSUER,
        }
        if settings.CLERK_AUDIENCE:
            decode_options["audience"] = settings.CLERK_AUDIENCE
        payload = jwt.decode(
            token,
            signing_key.key,
            **decode_options,
        )
        return {
            "user_id": payload.get("sub"),
            "email": payload.get("email"),
        }
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError as e:
        logger.warning("Invalid Clerk token: %s", e)
        raise HTTPException(status_code=401, detail="Invalid token")


async def get_optional_user(conn: HTTPConnection) -> dict | None:
    """Extract user if authenticated, return None otherwise."""
    try:
        return await get_current_user(conn)
    except HTTPException:
        return None
