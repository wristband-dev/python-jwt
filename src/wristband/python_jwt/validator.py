import json
import time
from typing import List, Optional, Union

from .jwks_client import JWKSClient, create_jwks_client
from .models import (
    JWKSClientConfig,
    JWTHeader,
    JWTPayload,
    JwtValidationResult,
    WristbandJwtValidator,
    WristbandJwtValidatorConfig,
)
from .utils import base64url_decode, validate_algorithm, verify_rs256_signature


class WristbandJwtValidatorImpl(WristbandJwtValidator):
    """
    Concrete implementation of the WristbandJwtValidator interface.

    Provides JWT validation capabilities, including Bearer token extraction, signature
    verification using JWKS, and comprehensive claim validation following OWASP security
    recommendations.

    Note:
        This class is not intended for direct instantiation by consumers.
        Use the `create_wristband_jwt_validator` factory function instead.
    """

    def __init__(self, jwks_client: JWKSClient, issuer: str, algorithms: Optional[List[str]] = ["RS256"]):
        """
        Create a new WristbandJwtValidatorImpl instance.

        Args:
            jwks_client: Configured JWKS client for key retrieval
            issuer: Expected issuer URL for token validation
            algorithms: Allowed signing algorithms (defaults to ['RS256'])
        """
        if not jwks_client:
            raise ValueError("JWKSClient must be provided to the validator.")
        if not issuer or not issuer.strip():
            raise ValueError("A valid issuer must be provided to the validator.")

        if (
            not algorithms
            or len(algorithms) != 1
            or not isinstance(algorithms[0], str)
            or algorithms[0].upper() != "RS256"
        ):
            raise ValueError("Only the RS256 algorithm is supported.")

        self._jwks_client = jwks_client  # JWKS client instance for fetching and caching signing keys.
        self._issuer = issuer  # Expected issuer claim value constructed from the Wristband application vanity domain.
        self._algorithms = algorithms  # List of allowed signing algorithms for security validation.

    def extract_bearer_token(self, authorization_header: Optional[Union[str, List[str]]] = None) -> str:
        """
        Extract the raw Bearer token from an HTTP Authorization header.

        Handles various input formats and validates the Bearer scheme according to RFC 6750.

        Valid cases:
        - extract_bearer_token('Bearer abc123')
        - extract_bearer_token(['Bearer abc123'])

        Invalid cases:
        - extract_bearer_token(['Bearer abc', 'Bearer xyz']) - Multiple headers
        - extract_bearer_token([]) - Empty array
        - extract_bearer_token(['']) - Empty string in array
        - extract_bearer_token(['Basic abc123']) - Wrong auth scheme

        Args:
            authorization_header: The Authorization header value(s)

        Returns:
            The extracted Bearer token string

        Raises:
            ValueError: When header is missing, malformed, contains multiple entries,
                       or uses wrong scheme
        """
        # Handle None/empty
        if not authorization_header:
            raise ValueError("No authorization header provided")

        # Handle array
        if isinstance(authorization_header, list):
            if len(authorization_header) == 0:
                raise ValueError("No authorization header provided")
            if len(authorization_header) > 1:
                raise ValueError("Multiple authorization headers not allowed")
            header_value = authorization_header[0]
        else:
            header_value = authorization_header

        # Handle empty string
        if not header_value or not header_value.strip():
            raise ValueError("No authorization header provided")

        if not header_value.startswith("Bearer "):
            raise ValueError('Authorization header must provide "Bearer" token')

        token = header_value[7:]  # Remove "Bearer " prefix
        if not token:
            raise ValueError("No token provided")

        return token

    def validate(self, token: str) -> JwtValidationResult:
        """
        Validate a JWT token using the Wristband JWKS endpoint and RS256 signature.

        Performs checks for:
        - Proper JWT structure
        - Supported algorithm (RS256)
        - Valid signature
        - Matching issuer
        - Expiration

        Args:
            token: A raw JWT token string

        Returns:
            A JwtValidationResult object indicating success or failure with details
        """
        if not token:
            return JwtValidationResult(is_valid=False, error_message="No token provided")

        parts = token.split(".")
        if len(parts) != 3:
            return JwtValidationResult(is_valid=False, error_message="Invalid JWT format")

        header_b64, payload_b64, signature_b64 = parts

        # Decode header and payload
        try:
            header_dict = json.loads(base64url_decode(header_b64))
            payload_dict = json.loads(base64url_decode(payload_b64))
            header = JWTHeader(header_dict)
            payload = JWTPayload(payload_dict)
        except Exception:
            return JwtValidationResult(is_valid=False, error_message="Invalid JWT encoding")

        # Validate algorithm using OWASP-recommended practices
        if not validate_algorithm(header.alg, self._algorithms):
            return JwtValidationResult(
                is_valid=False,
                error_message=f"Algorithm {header.alg} not allowed. Expected one of: {', '.join(self._algorithms)}",
            )

        # Validate issuer
        if payload.iss != self._issuer:
            return JwtValidationResult(
                is_valid=False,
                error_message=f"Invalid issuer. Expected {self._issuer}, got {payload.iss}",
            )

        # Validate expiration
        current_time = int(time.time())
        if payload.exp and current_time >= payload.exp:
            return JwtValidationResult(is_valid=False, error_message="Token has expired")

        # Validate not before
        if payload.nbf and current_time < payload.nbf:
            return JwtValidationResult(is_valid=False, error_message="Token not yet valid")

        # Get signing key and verify signature
        if not header.kid:
            return JwtValidationResult(is_valid=False, error_message="Token header missing kid (key ID)")

        try:
            public_key = self._jwks_client.get_signing_key(header.kid)
        except Exception as error:
            return JwtValidationResult(is_valid=False, error_message=f"Failed to get signing key: {error}")

        # Verify signature using OWASP-compliant crypto
        signature_valid = verify_rs256_signature(f"{header_b64}.{payload_b64}", signature_b64, public_key)
        if not signature_valid:
            return JwtValidationResult(is_valid=False, error_message="Invalid signature")

        # Validation Success
        return JwtValidationResult(is_valid=True, payload=payload)


def create_wristband_jwt_validator(config: WristbandJwtValidatorConfig) -> WristbandJwtValidator:
    """
    Factory function for creating a configured Wristband JWT validator instance.

    The created validator is thread-safe and should be reused across requests to
    benefit from JWKS key caching and connection pooling.

    Args:
        config: Configuration object containing Wristband domain and cache settings

    Returns:
        Configured WristbandJwtValidator instance ready for token validation

    Example:
        ```python
        from wristband.python_jwt import create_wristband_jwt_validator, WristbandJwtValidatorConfig

        # Create validator instance (reuse across requests)
        validator = create_wristband_jwt_validator(
            WristbandJwtValidatorConfig(
                wristband_application_vanity_domain='myapp.wristband.dev'
            )
        )

        # FastAPI route handler example usage
        @app.get("/protected")
        def protected_route(request: Request):
            try:
                auth_header = request.headers.get("authorization")
                token = validator.extract_bearer_token(auth_header)
                result = validator.validate(token)

                if result.is_valid:
                    return {"user": result.payload.sub, "message": "Access granted"}
                else:
                    raise HTTPException(status_code=401, detail=result.error_message)
            except ValueError as error:
                raise HTTPException(status_code=401, detail="Authentication required")
        ```
    """
    issuer = f"https://{config.wristband_application_vanity_domain}"
    jwks_client = create_jwks_client(
        JWKSClientConfig(
            jwks_uri=f"{issuer}/api/v1/oauth2/jwks",
            cache_max_size=config.jwks_cache_max_size or 20,
            cache_ttl=config.jwks_cache_ttl,  # None if not set (cached indefinitely)
        )
    )
    return WristbandJwtValidatorImpl(jwks_client, issuer, ["RS256"])
