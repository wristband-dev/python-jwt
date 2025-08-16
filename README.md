<div align="center">
  <a href="https://wristband.dev">
    <picture>
      <img src="https://assets.wristband.dev/images/email_branding_logo_v1.png" alt="Wristband" width="297" height="64">
    </picture>
  </a>
  <p align="center">
    Enterprise-ready auth that is secure by default, truly multi-tenant, and ungated for small businesses.
  </p>
  <p align="center">
    <b>
      <a href="https://wristband.dev">Website</a> • 
      <a href="https://docs.wristband.dev/">Documentation</a>
    </b>
  </p>
</div>

<br/>

---

<br/>

# Wristband JWT Validation SDK for Python

This framework-agnostic Python SDK validates JWT access tokens issued by Wristband for user or machine authentication. It uses the Wristband JWKS endpoint to resolve signing keys and verify RS256 signatures. Validation includes issuer verification, lifetime checks, and signature validation using cached keys. Developers should use this to protect routes and ensure that only valid, Wristband-issued access tokens can access secured APIs.

You can learn more about JWTs in Wristband in our documentation:

- [JWTs and Signing Keys](https://docs.wristband.dev/docs/json-web-tokens-jwts-and-signing-keys)

<br/>

## Requirements

This SDK is designed to work with Python 3.9+ and any Python framework (FastAPI, Django, Flask, etc.). It uses minimal dependencies for maximum compatibility and security.

<br/>

## 1) Installation

```bash
pip install wristband-python-jwt
```

or

```bash
poetry add wristband-python-jwt
```

or

```bash
pipenv install wristband-python-jwt
```

You should see the dependency added to your `requirements.txt` file:

```txt
wristband-python-jwt==0.1.0
```

Or in your `pyproject.toml`:

```txt
dependencies = [
    "wristband-python-jwt==0.1.0",
    # ...other dependencies...
]
```

Or in your `Pipfile`:
```txt
[packages]
wristband-python-jwt = "==0.1.0"
```

<br/>

## 2) Wristband Configuration

First, you'll need to make sure you have an Application in your Wristband Dashboard account. If you haven't done so yet, refer to our docs on [Creating an Application](https://docs.wristband.dev/docs/quick-start-create-a-wristband-application).

**Make sure to copy the Application Vanity Domain for next steps, which can be found in "Application Settings" for your Wristband Application.**

<br/>

## 3) SDK Configuration

First, create an instance of `WristbandJwtValidator` in your server's directory structure in any location of your choice (i.e.: `src/wristband.py`). Then, you can export this instance and use it across your project. When creating an instance, you provide all necessary configurations for your application to correlate with how you've set it up in Wristband.

```python
# src/wristband.py
from wristband.python_jwt import create_wristband_jwt_validator, WristbandJwtValidatorConfig

wristband_jwt_validator = create_wristband_jwt_validator(
    WristbandJwtValidatorConfig(
        wristband_application_vanity_domain='auth.yourapp.io'
    )
)
```

<br/>

## 4) Extract and Validate JWT Tokens

The SDK provides methods to extract Bearer tokens from Authorization headers and validate them. Here are examples for a few frameworks:

### FastAPI

```python
# jwt_auth_middleware.py
from fastapi import Request, Response, status
from starlette.middleware.base import BaseHTTPMiddleware
from .wristband import wristband_jwt_validator

class JwtAuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Adjust paths as needed
        if not request.url.path.startswith('/api/protected/'):
            return await call_next(request)
        
        try:
            auth_header = request.headers.get("authorization")
            token = wristband_jwt_validator.extract_bearer_token(auth_header)
            result = wristband_jwt_validator.validate(token)
            
            if not result.is_valid:
                print(f"JWT validation middleware error: {result.error_message}")
                return Response(status_code=status.HTTP_401_UNAUTHORIZED)
            
            return await call_next(request)
            
        except Exception as error:
            print(f"JWT validation middleware error: {error}")
            return Response(status_code=status.HTTP_401_UNAUTHORIZED)

# main.py
from fastapi import FastAPI, Request
from .middleware import JwtAuthMiddleware

app = FastAPI()

# Add JWT authentication middleware
app.add_middleware(JwtAuthMiddleware)

@app.get("/api/protected/data")
async def protected_data(request: Request):
    return { "message": "Hello from protected API!" }
```

<br/>

### Django

```python
# your_app/jwt_auth_middleware.py
from django.http import HttpResponse
from django.utils.deprecation import MiddlewareMixin
from .wristband import wristband_jwt_validator

class JwtAuthMiddleware(MiddlewareMixin):
    def process_request(self, request):
        # Adjust paths as needed
        if not request.path.startswith('/api/protected/'):
            return None
            
        try:
            auth_header = request.META.get('HTTP_AUTHORIZATION')
            token = wristband_jwt_validator.extract_bearer_token(auth_header)
            result = wristband_jwt_validator.validate(token)
            
            if not result.is_valid:
                print(f"JWT validation middleware error: {result.error_message}")
                return HttpResponse(status=401)

        except Exception as error:
            print(f"JWT validation middleware error: {error}")
            return HttpResponse(status=401)

# your_project/settings.py
MIDDLEWARE = [
    # ...other middlewares...
    'your_app.middleware.JwtAuthMiddleware',  # Add your JWT middleware
]

# your_project/urls.py
from django.contrib import admin
from django.urls import path
from your_app import views

urlpatterns = [
    # The JWT middleware will execute before the business logic occurs.
    path('api/protected/data/', views.protected_view, name='protected_data'),
    # ...other URLs...
]
```

<br/>

### Flask

```python
# jwt_auth_middleware.py
from flask import request, jsonify, g
from functools import wraps
from .wristband import wristband_jwt_validator

def jwt_auth_middleware():
    # Adjust paths as needed
    if not request.path.startswith('/api/protected/'):
        return None
        
    try:
        auth_header = request.headers.get('Authorization')
        token = wristband_jwt_validator.extract_bearer_token(auth_header)
        result = wristband_jwt_validator.validate(token)
        
        if not result.is_valid:
            print(f"JWT validation middleware error: {result.error_message}")
            return '', 401

    except Exception as error:
        print(f"JWT validation middleware error: {error}")
        return '', 401

# app.py
from flask import Flask, jsonify
from .middleware import jwt_auth_middleware

app = Flask(__name__)

# Register JWT middleware to run before each request
app.before_request(jwt_auth_middleware)

@app.route('/api/protected/data', methods=['GET'])
def protected_data():
    return jsonify({"message": "Hello from protected API!"})

if __name__ == '__main__':
    app.run(debug=True)
```

<br/>

## JWKS Caching and Expiration

The SDK automatically retrieves and caches JSON Web Key Sets (JWKS) from your Wristband application's domain to validate incoming access tokens. By default, keys are cached in memory and reused across requests to avoid unnecessary network calls.

You can control how the SDK handles this caching behavior using two optional configuration values: `jwks_cache_max_size` and `jwks_cache_ttl`.

**Set a limit on how many keys to keep in memory:**
```python
validator = create_wristband_jwt_validator(
    WristbandJwtValidatorConfig(
        wristband_application_vanity_domain='auth.yourapp.io',
        jwks_cache_max_size=10  # Keep at most 10 keys in cache
    )
)
```

**Set a time-to-live duration for each key:**
```python
validator = create_wristband_jwt_validator(
    WristbandJwtValidatorConfig(
        wristband_application_vanity_domain='auth.yourapp.io',
        jwks_cache_ttl=2629746000  # Expire keys from cache after 1 month (in milliseconds)
    )
)
```

If `jwks_cache_ttl` is not set, cached keys remain available until evicted by the cache size limit.

<br>

## SDK Configuration Options

| JWT Validation Option | Type | Required | Description |
| --------------------- | ---- | -------- | ----------- |
| jwks_cache_max_size | int | No | Maximum number of JWKs to cache in memory. When exceeded, the least recently used keys are evicted. Defaults to 20. |
| jwks_cache_ttl | int | No | Time-to-live for cached JWKs, in milliseconds. If not set, keys remain in cache until eviction by size limit. |
| wristband_application_vanity_domain | str | Yes | The Wristband vanity domain used to construct the JWKS endpoint URL for verifying tokens. Example: `myapp.wristband.dev`. |

<br/>

## API Reference

### `create_wristband_jwt_validator(config)`

This is a factory function that creates a configured JWT validator instance.

**Parameters:**
| Name | Type | Required | Description |
| ---- | ---- | -------- | ----------- |
| config | `WristbandJwtValidatorConfig` | Yes | Configuration options (see [SDK Configuration Options](#sdk-configuration-options)) |

**Returns:**
- The configured `WristbandJwtValidator` instance

**Example:**
```python
validator = create_wristband_jwt_validator(
    WristbandJwtValidatorConfig(
        wristband_application_vanity_domain='myapp.wristband.dev',
        jwks_cache_max_size=20,
        jwks_cache_ttl=3600000
    )
)
```

<br/>

### `extract_bearer_token(authorization_header)`

This is used to extract the raw Bearer token from an HTTP Authorization header. It can handle various input formats and validates the Bearer scheme according to [RFC 6750](https://datatracker.ietf.org/doc/html/rfc6750).

The function will raise an error for the following cases:
- The Authorization header is missing
- The Authorization header is malformed
- The Authorization header contains multiple entries
- The Authorization header uses wrong scheme (i.e. not using `Bearer`)
- The Authorization header is missing the token value

**Parameters:**
| Name | Type | Required | Description |
| ---- | ---- | -------- | ----------- |
| authorization_header | str or list[str] | Yes | The Authorization header value(s) of the current request. |

**Returns:**
| Type | Description |
| ---- | ----------- |
| str | The extracted Bearer token |

**Valid usage examples:**
```python
token1 = wristband_jwt_validator.extract_bearer_token('Bearer abc123')
token2 = wristband_jwt_validator.extract_bearer_token(['Bearer abc123'])
# From FastAPI request
token3 = wristband_jwt_validator.extract_bearer_token(request.headers.get('authorization'))
# From Django request
token4 = wristband_jwt_validator.extract_bearer_token(request.META.get('HTTP_AUTHORIZATION'))
```

**Invalid cases that raise errors:**
```python
wristband_jwt_validator.extract_bearer_token(['Bearer abc', 'Bearer xyz'])
wristband_jwt_validator.extract_bearer_token([])
wristband_jwt_validator.extract_bearer_token('Basic abc123')
wristband_jwt_validator.extract_bearer_token('Bearer ')
```

### `validate(token)`

Validates a JWT access token issued by Wristband. Performs comprehensive validation including format checking, signature verification, issuer validation, and expiration checks.

**Parameters:**
| Name | Type | Required | Description |
| ---- | ---- | -------- | ----------- |
| token | str | Yes | The Wristband JWT token to validate. |

**Returns:**
| Type | Description |
| ---- | ----------- |
| `JwtValidationResult` | Validation result object. |

JwtValidationResult attributes:
```python
class JwtValidationResult:
    is_valid: bool
    payload: Optional[JWTPayload]     # Present when is_valid is True
    error_message: Optional[str]      # Present when is_valid is False
```

JWTPayload properties:
```python
class JWTPayload:
    iss: Optional[str]                    # Issuer
    sub: Optional[str]                    # Subject (user ID)
    aud: Optional[Union[str, List[str]]]  # Audience
    exp: Optional[int]                    # Expiration time (Unix timestamp)
    nbf: Optional[int]                    # Not before (Unix timestamp)
    iat: Optional[int]                    # Issued at (Unix timestamp)
    jti: Optional[str]                    # JWT ID
    # ... plus any additional Wristband custom claims...
```

**Valid usage examples:**
```python
result = validator.validate(token)

if result.is_valid:
    print('User ID:', result.payload.sub)
    print('Expires at:', datetime.fromtimestamp(result.payload.exp))
else:
    print('Validation failed:', result.error_message)
```

<br/>

## Questions

Reach out to the Wristband team at <support@wristband.dev> for any questions regarding this SDK.

<br/>
