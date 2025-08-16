"""
Wristband JWT Validation SDK for Python.

Framework-agnostic Python SDK for validating JWT access tokens issued by Wristband
for user or machine authentication. Uses the Wristband JWKS endpoint to resolve
signing keys and verify RS256 signatures.

Example:
    ```python
    from wristband.python_jwt import create_wristband_jwt_validator, WristbandJwtValidatorConfig

    # Create validator instance (reuse across requests)
    validator = create_wristband_jwt_validator(
        WristbandJwtValidatorConfig(wristband_application_vanity_domain='myapp.wristband.dev')
    )

    # Extract and validate token
    def verify_token(authorization_header):
        try:
            token = validator.extract_bearer_token(authorization_header)
            result = await validator.validate(token)

            if result.is_valid:
                return result.payload
            else:
                raise ValueError(result.error_message)
        except Exception as error:
            raise ValueError(f"Authentication failed: {error}")
    ```
"""

from .models import (
    JWTPayload,
    JwtValidationResult,
    WristbandJwtValidator,
    WristbandJwtValidatorConfig,
)
from .validator import create_wristband_jwt_validator

__all__ = [
    "WristbandJwtValidator",
    "WristbandJwtValidatorConfig",
    "JWTPayload",
    "JwtValidationResult",
    "create_wristband_jwt_validator",
]
