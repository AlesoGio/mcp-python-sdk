import json
import time
from typing import Any

from pydantic import AnyHttpUrl
from starlette.authentication import AuthCredentials, AuthenticationBackend, SimpleUser
from starlette.requests import HTTPConnection
from starlette.types import Receive, Scope, Send

from mcp.server.auth.provider import AccessToken, TokenVerifier


class AuthenticatedUser(SimpleUser):
    """User with authentication info."""

    def __init__(self, auth_info: AccessToken):
        super().__init__(auth_info.client_id)
        self.access_token = auth_info
        self.scopes = auth_info.scopes


class BearerAuthBackend(AuthenticationBackend):
    """
    Authentication backend that validates Bearer tokens using a TokenVerifier.
    """

    def __init__(self, token_verifier: TokenVerifier):
        self.token_verifier = token_verifier

    async def authenticate(self, conn: HTTPConnection):
        auth_header = next(
            (conn.headers.get(key) for key in conn.headers if key.lower() == "authorization"),
            None,
        )

        print(f"[AUTH] Incoming headers: {dict(conn.headers)}")

        if not auth_header:
            print("[AUTH] Missing Authorization header")
            return None

        if not auth_header.lower().startswith("bearer "):
            print("[AUTH] Malformed Authorization header")
            return None

        token = auth_header[7:]  # Remove "Bearer " prefix
        print(f"[AUTH] Extracted token: {token}")

        try:
            # Validate the token with the verifier
            auth_info = await self.token_verifier.verify_token(token)
            print(f"[AUTH] Token verification result: {auth_info}")
        except Exception as e:
            print(f"[AUTH] Exception during token verification: {e}")
            return None

        if not auth_info:
            print("[AUTH] Invalid token: verification returned None")
            return None

        if auth_info.expires_at and auth_info.expires_at < int(time.time()):
            print("[AUTH] Token expired")
            return None

        print(f"[AUTH] Token valid. Scopes: {auth_info.scopes}")
        return AuthCredentials(auth_info.scopes), AuthenticatedUser(auth_info)



class RequireAuthMiddleware:
    """
    Middleware that requires a valid Bearer token in the Authorization header.

    This will validate the token with the auth provider and store the resulting
    auth info in the request state.
    """

    def __init__(
        self,
        app: Any,
        required_scopes: list[str],
        resource_metadata_url: AnyHttpUrl | None = None,
    ):
        """
        Initialize the middleware.

        Args:
            app: ASGI application
            required_scopes: List of scopes that the token must have
            resource_metadata_url: Optional protected resource metadata URL for WWW-Authenticate header
        """
        self.app = app
        self.required_scopes = required_scopes
        self.resource_metadata_url = resource_metadata_url

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        auth_user = scope.get("user")
        if not isinstance(auth_user, AuthenticatedUser):
            await self._send_auth_error(
                send, status_code=401, error="invalid_token", description="Authentication required"
            )
            return

        auth_credentials = scope.get("auth")

        for required_scope in self.required_scopes:
            # auth_credentials should always be provided; this is just paranoia
            if auth_credentials is None or required_scope not in auth_credentials.scopes:
                await self._send_auth_error(
                    send, status_code=403, error="insufficient_scope", description=f"Required scope: {required_scope}"
                )
                return

        await self.app(scope, receive, send)

    async def _send_auth_error(self, send: Send, status_code: int, error: str, description: str) -> None:
        """Send an authentication error response with WWW-Authenticate header."""
        # Build WWW-Authenticate header value
        www_auth_parts = [f'error="{error}"', f'error_description="{description}"']
        if self.resource_metadata_url:
            www_auth_parts.append(f'resource_metadata="{self.resource_metadata_url}"')

        www_authenticate = f"Bearer {', '.join(www_auth_parts)}"

        # Send response
        body = {"error": error, "error_description": description}
        body_bytes = json.dumps(body).encode()

        await send(
            {
                "type": "http.response.start",
                "status": status_code,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body_bytes)).encode()),
                    (b"www-authenticate", www_authenticate.encode()),
                ],
            }
        )

        await send(
            {
                "type": "http.response.body",
                "body": body_bytes,
            }
        )
