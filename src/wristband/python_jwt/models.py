from typing import Any, Dict, List, Optional, Protocol, Union, cast

# ////////////////////////////////////
#  EXTERNAL TYPES
# ////////////////////////////////////


class WristbandJwtValidator(Protocol):
    """
    Interface for validating and extracting Bearer tokens from JWTs issued by Wristband.

    This is the main entry point for verifying token authenticity, issuer, expiration,
    and signature against the Wristband JWKS endpoint.
    """

    def extract_bearer_token(self, authorization_header: Optional[Union[str, List[str]]] = None) -> str:
        """
        Extract the raw Bearer token from an HTTP Authorization header.

        Args:
            authorization_header: The value of the Authorization header, which may be:
                - A string (e.g., "Bearer abc123")
                - A list containing a single string
                - None

        Returns:
            The raw token string (e.g., "abc123") if valid

        Raises:
            ValueError: If the header is missing, malformed, contains multiple entries,
                       or uses a non-Bearer scheme
        """
        ...

    def validate(self, token: str) -> "JwtValidationResult":
        """
        Validate a JWT token using the Wristband JWKS endpoint and RS256 signature.

        Performs checks for:
        - Proper JWT structure
        - Supported algorithm (RS256)
        - Valid signature
        - Matching issuer
        - Expiration (exp) and not-before (nbf) claims

        Args:
            token: A raw JWT token string

        Returns:
            A JwtValidationResult object indicating success or failure with details
        """
        ...


class WristbandJwtValidatorConfig:
    """
    Configuration options for Wristband JWT validation.

    Attributes:
        wristband_application_vanity_domain: The Wristband application vanity domain.
            This value is used to construct the JWKS endpoint URL for token validation.
        jwks_cache_max_size: The maximum number of JWK keys to cache. When this limit
            is reached, the least recently used keys will be evicted from the cache.
            Defaults to 20.
        jwks_cache_ttl: The time-to-live for cached JWK keys, in milliseconds.
            If None (the default), keys are cached indefinitely until evicted due
            to the cache size limit.
    """

    def __init__(
        self,
        wristband_application_vanity_domain: str,
        jwks_cache_max_size: Optional[int] = None,
        jwks_cache_ttl: Optional[int] = None,
    ):
        self.wristband_application_vanity_domain = wristband_application_vanity_domain
        self.jwks_cache_max_size = jwks_cache_max_size
        self.jwks_cache_ttl = jwks_cache_ttl


class JWTPayload:
    """
    Standard JWT payload structure containing common claims and custom properties.

    Follows RFC 7519 specifications for JSON Web Token claims.
    """

    def __init__(self, payload_dict: Dict[str, Any]):
        """Initialize JWT payload from dictionary."""
        self._payload = payload_dict

    @property
    def iss(self) -> Optional[str]:
        """Issuer claim - identifies the principal that issued the JWT."""
        return self._payload.get("iss")

    @property
    def sub(self) -> Optional[str]:
        """Subject claim - identifies the principal that is the subject of the JWT."""
        return self._payload.get("sub")

    @property
    def aud(self) -> Optional[Union[str, List[str]]]:
        """Audience claim - identifies the recipients that the JWT is intended for."""
        return self._payload.get("aud")

    @property
    def exp(self) -> Optional[int]:
        """
        Expiration time claim - identifies the expiration time on or after which
        the JWT must not be accepted for processing (Unix timestamp).
        """
        return self._payload.get("exp")

    @property
    def nbf(self) -> Optional[int]:
        """
        Not before claim - identifies the time before which the JWT must not be
        accepted for processing (Unix timestamp).
        """
        return self._payload.get("nbf")

    @property
    def iat(self) -> Optional[int]:
        """
        Issued at claim - identifies the time at which the JWT was issued
        (Unix timestamp).
        """
        return self._payload.get("iat")

    @property
    def jti(self) -> Optional[str]:
        """JWT ID claim - provides a unique identifier for the JWT."""
        return self._payload.get("jti")

    def get(self, key: str, default: Any = None) -> Any:
        """Get any additional claim from the payload."""
        return self._payload.get(key, default)

    def __getitem__(self, key: str) -> Any:
        """Allow dict-like access to payload claims."""
        return self._payload[key]

    def __contains__(self, key: str) -> bool:
        """Allow 'in' operator for checking claim existence."""
        return key in self._payload

    def to_dict(self) -> Dict[str, Any]:
        """Return the underlying payload dictionary."""
        return self._payload.copy()


class JwtValidationResult:
    """
    Result object returned by JWT validation.

    Contains validation status, decoded payload on success, or error details on failure.
    """

    def __init__(
        self,
        is_valid: bool,
        payload: Optional[JWTPayload] = None,
        error_message: Optional[str] = None,
    ):
        """
        Initialize validation result.

        Args:
            is_valid: Flag indicating whether the token is valid or not
            payload: Decoded JWT payload, if valid
            error_message: Error message, if validation failed
        """
        self.is_valid = is_valid
        self.payload = payload
        self.error_message = error_message


# ////////////////////////////////////
#  INTERNAL TYPES
# ////////////////////////////////////


class JWKSClientConfig:
    """
    Configuration options for the JWKS (JSON Web Key Set) client.
    """

    def __init__(
        self,
        jwks_uri: str,
        cache_max_size: Optional[int] = None,
        cache_ttl: Optional[int] = None,
    ):
        """
        Initialize JWKS client configuration.

        Args:
            jwks_uri: The URI endpoint for fetching the JSON Web Key Set
            cache_max_size: Maximum number of keys to store in the cache
            cache_ttl: Time-to-live for cached keys, in milliseconds. If None,
                      keys are cached indefinitely until evicted
        """
        self.jwks_uri = jwks_uri
        self.cache_max_size = cache_max_size
        self.cache_ttl = cache_ttl


class JWKSKey:
    """
    Represents a single JSON Web Key (JWK) as defined in RFC 7517.

    Contains the cryptographic key material and metadata needed for JWT signature
    verification.
    """

    def __init__(self, key_dict: Dict[str, Any]):
        """Initialize JWK from dictionary."""
        self._key = key_dict

    @property
    def kty(self) -> str:
        """Key type parameter - identifies the cryptographic algorithm family."""
        return cast(str, self._key["kty"])

    @property
    def kid(self) -> str:
        """Key ID parameter - used to match a specific key during verification."""
        return cast(str, self._key["kid"])

    @property
    def use(self) -> str:
        """Public key use parameter - identifies the intended use of the public key."""
        return cast(str, self._key["use"])

    @property
    def n(self) -> str:
        """RSA modulus parameter (base64url-encoded)."""
        return cast(str, self._key["n"])

    @property
    def e(self) -> str:
        """RSA exponent parameter (base64url-encoded)."""
        return cast(str, self._key["e"])

    @property
    def alg(self) -> str:
        """Algorithm parameter - identifies the algorithm intended for use with the key."""
        return cast(str, self._key["alg"])


class JWKSResponse:
    """
    Response structure from the JWKS endpoint.

    Contains an array of JWK keys used for JWT signature verification.
    """

    def __init__(self, response_dict: Dict[str, Any]):
        """Initialize JWKS response from dictionary."""
        self.keys = [JWKSKey(key) for key in response_dict.get("keys", [])]


class JWTHeader:
    """
    JWT header structure containing algorithm and type information.

    Represents the header portion of a JSON Web Token as defined in RFC 7519.
    """

    def __init__(self, header_dict: Dict[str, Any]):
        """Initialize JWT header from dictionary."""
        self._header = header_dict

    @property
    def alg(self) -> str:
        """
        Algorithm parameter - identifies the cryptographic algorithm used to secure the JWT.
        For Wristband tokens, this should be "RS256".
        """
        return cast(str, self._header["alg"])

    @property
    def typ(self) -> str:
        """Type parameter - declares the media type of the JWT."""
        return cast(str, self._header["typ"])

    @property
    def kid(self) -> str:
        """
        Key ID parameter - hints about which key was used to secure the JWT.
        Used to match against the corresponding JWK during verification.
        """
        return cast(str, self._header["kid"])


class CacheOptions:
    """
    Configuration options for the LRU cache instance.
    """

    def __init__(self, max_size: int, ttl: Optional[int] = None):
        """
        Initialize cache options.

        Args:
            max_size: Maximum number of entries to store in the cache. When this limit
                     is exceeded, the least recently used entry will be evicted.
                     Must be a positive integer.
            ttl: Optional time-to-live for cache entries, in milliseconds. If specified,
                entries will be automatically considered expired and removed after this
                duration, regardless of access patterns. If None, entries will only be
                evicted due to size constraints.
        """
        if not isinstance(max_size, int) or max_size <= 0:
            raise ValueError("max_size must be a positive integer")
        if ttl is not None and (not isinstance(ttl, int) or ttl <= 0):
            raise ValueError("ttl must be a positive integer (if specified)")

        self.max_size = max_size
        self.ttl = ttl


class LRUNode:
    """
    Node in the doubly-linked list for LRU cache operations.
    """

    def __init__(
        self,
        key: str = "",
        value: str = "",
        last_accessed: int = 0,
        prev: Optional["LRUNode"] = None,
        next: Optional["LRUNode"] = None,
    ):
        """
        Initialize LRU node.

        Args:
            key: The cache key for this entry
            value: The cached JWK value
            last_accessed: Timestamp when this entry was last accessed, in milliseconds from Unix epoch
            prev: Pointer to the previous node in the doubly-linked list (None for head)
            next: Pointer to the next node in the doubly-linked list (None for tail)
        """
        self.key = key
        self.value = value
        self.last_accessed = last_accessed
        self.prev = prev
        self.next = next
