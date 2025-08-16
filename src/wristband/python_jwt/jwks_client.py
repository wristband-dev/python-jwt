import time
from typing import Dict

import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from .models import CacheOptions, JWKSClientConfig, JWKSKey, JWKSResponse
from .utils import LRUCache, base64url_decode_bytes

JWKS_RETRY_DELAY_MS = 100
JWKS_MAX_ATTEMPTS = 3


class JWKSClient:
    """
    Internal JWKS (JSON Web Key Set) client for fetching Wristband keys.

    This client handles the complexities of JWKS key retrieval, validation, conversion,
    and caching for JWT signature verification. It implements security best practices
    and efficient LRU caching to minimize network requests.

    Key features:
    - Automatic key fetching from Wristband JWKS endpoint
    - LRU caching with configurable TTL to reduce network overhead
    - Security validation ensuring keys meet OWASP strength requirements
    - Format conversion from JWK to PEM format for cryptography library compatibility
    - Error handling with descriptive messages for debugging

    The client is designed for internal use by the JWT validator and handles all the
    low-level details of JWKS protocol compliance and cryptographic key management.

    Note:
        This class is not intended for direct external use
    """

    def __init__(self, config: JWKSClientConfig):
        """
        Create a new JWKS client with the specified configuration.

        Initializes the internal LRU cache with the provided size and TTL settings.
        The cache stores converted PEM keys indexed by their key ID (kid) for fast retrieval.

        Args:
            config: Configuration object specifying JWKS endpoint and cache settings

        Example:
            ```python
            client = JWKSClient(JWKSClientConfig(
                jwks_uri='https://myapp.wristband.dev/api/v1/oauth2/jwks',
                cache_max_size=10,
                cache_ttl=7889238000  # 3 months
            ))
            ```
        """
        if not config or not config.jwks_uri or not config.jwks_uri.strip():
            raise ValueError("A valid JWKS URI is required.")

        # None TTL = cached indefinitely
        cache_options = CacheOptions(max_size=config.cache_max_size or 20, ttl=config.cache_ttl)
        self._cache = LRUCache(cache_options)  # LRU cache instance for storing converted PEM keys.
        self._jwks_uri = config.jwks_uri  # The URI endpoint for fetching the JSON Web Key Set.

    def get_signing_key(self, kid: str) -> str:
        """
        Retrieve a signing key by its key ID, with automatic caching and format conversion.

        This method implements the complete JWKS key retrieval workflow:
        1. Check LRU cache for previously converted key
        2. If not cached, fetch complete JWKS from Wristband
        3. Find the specific key by ID within the key set
        4. Validate key type and cryptographic strength
        5. Convert from JWK format to PEM format for cryptography library
        6. Cache the converted key for future use
        7. Return the PEM-formatted public key

        Args:
            kid: The key ID (kid) to retrieve from the JWKS endpoint

        Returns:
            The public key in PEM format

        Raises:
            ValueError: If JWKS fetch fails, key not found, non-RSA key, weak key
                       (<2048 bits), or PEM conversion fails.

        Example:
            ```python
            try:
                public_key = client.get_signing_key('kid-abc123')
                # public_key is now in PEM format ready for cryptography library
                print('Retrieved key for verification')
            except ValueError as error:
                if 'Unable to find' in str(error):
                    print('Key ID not found in JWKS')
                elif 'RSA key too weak' in str(error):
                    print('Key does not meet security requirements')
                else:
                    print(f'JWKS fetch failed: {error}')
            ```
        """
        # Check cache first using proper LRU cache
        cached_key = self._cache.get(kid)
        if cached_key:
            return cached_key

        # Fetch JWKS from Wristband
        jwks = self._fetch_jwks_with_retry()
        jwk = None
        for key in jwks.keys:
            if key.kid == kid:
                jwk = key
                break

        if not jwk:
            raise ValueError(f"Unable to find a signing key that matches '{kid}'")

        if jwk.kty != "RSA":
            raise ValueError("Only RSA keys are supported")

        # Convert JWK to PEM
        public_key = self._jwk_to_pem(jwk)

        # Cache the key using LRU cache
        self._cache.set(kid, public_key)

        return public_key

    def clear(self) -> None:
        """
        Clear all cached keys from the internal cache.

        Useful for testing scenarios or when a complete cache invalidation is needed,
        such as during key rotation events or security incidents.

        Example:
            ```python
            # Clear cache during testing
            client.clear()

            # Emergency cache flush during security incident
            if security_incident:
                client.clear()
                print('JWKS cache cleared for security')
            ```
        """
        self._cache.clear()

    def get_cache_stats(self) -> Dict[str, int]:
        """
        Return cache statistics for monitoring and debugging purposes.

        Provides insights into cache utilization, which can be useful for:
        - Performance monitoring and optimization
        - Capacity planning for cache size configuration
        - Debugging cache behavior in production

        Returns:
            Dictionary containing current cache statistics

        Example:
            ```python
            stats = client.get_cache_stats()
            print(f"JWKS cache: {stats['size']}/{stats['max_size']} entries")

            # Monitor cache efficiency
            if stats['size'] >= stats['max_size'] * 0.9:
                print('JWKS cache nearing capacity')
            ```
        """
        return self._cache.get_stats()

    def _fetch_jwks_with_retry(self) -> JWKSResponse:
        """
        Fetch JWKS from the endpoint with retry logic.

        Attempts up to 3 times with 100ms delay between attempts.

        Returns:
            The JWKS response

        Raises:
            ValueError: If all retry attempts fail
        """
        for attempt in range(1, JWKS_MAX_ATTEMPTS + 1):
            try:
                with httpx.Client(timeout=15.0) as client:
                    response = client.get(self._jwks_uri)
                    response.raise_for_status()

                    return JWKSResponse(response.json())
            except Exception as error:
                is_last_attempt = attempt == JWKS_MAX_ATTEMPTS

                if is_last_attempt:
                    raise ValueError(f"Failed to fetch JWKS after {JWKS_MAX_ATTEMPTS} attempts: {error}")

                # Wait before next attempt
                time.sleep(JWKS_RETRY_DELAY_MS / 1000)

        # This should never be reached
        raise ValueError("Unexpected error in JWKS fetch retry logic")

    def _jwk_to_pem(self, jwk: JWKSKey) -> str:
        """
        Convert a JSON Web Key (JWK) to PEM format for cryptography library compatibility.

        The conversion includes:
        - Security validation of key strength
        - Proper ASN.1 DER encoding of RSA parameters
        - PEM formatting with correct headers and line breaks

        Security features:
        - Validates RSA key strength (minimum 2048 bits per OWASP)
        - Ensures required JWK parameters (n, e) are present
        - Implements proper cryptographic encoding standards

        Args:
            jwk: The JSON Web Key to convert

        Returns:
            PEM-formatted RSA public key string

        Raises:
            ValueError: If required JWK parameters (n, e) are missing, RSA key is below
                       2048-bit minimum security requirement, or PEM formatting fails.

        Note:
            This method is used internally by get_signing_key()

        Example:
            ```python
            # Internal usage - converts JWK like this:
            jwk = JWKSKey({
                'alg': 'RS256',
                'kty': 'RSA',
                'kid': 'abc123',
                'n': '<base64url-encoded-modulus>',
                'e': 'AQAB',
                'use': 'sig'
            })

            # To PEM format like this:
            # -----BEGIN PUBLIC KEY-----
            # MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
            # -----END PUBLIC KEY-----
            ```
        """
        if not jwk.n or not jwk.e:
            raise ValueError("Invalid JWK: missing n or e parameters")

        # Validate key strength
        n_bytes = base64url_decode_bytes(jwk.n)
        key_bit_length = len(n_bytes) * 8
        if key_bit_length < 2048:
            raise ValueError(f"RSA key too weak: {key_bit_length} bits. 2048 bits minimum required.")

        # Convert JWK to RSA public key using cryptography library
        try:
            # Decode RSA parameters
            n_int = int.from_bytes(n_bytes, byteorder="big")
            e_bytes = base64url_decode_bytes(jwk.e)
            e_int = int.from_bytes(e_bytes, byteorder="big")

            # Create RSA public key
            public_numbers = rsa.RSAPublicNumbers(e_int, n_int)
            public_key = public_numbers.public_key()

            # Convert to PEM format
            pem_bytes = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )

            return pem_bytes.decode("utf-8")

        except Exception as e:
            raise ValueError(f"Failed to convert JWK to PEM: {e}")


def create_jwks_client(config: JWKSClientConfig) -> JWKSClient:
    """
    Factory function for creating a configured JWKS client instance.

    Args:
        config: Configuration object specifying JWKS endpoint and cache settings

    Returns:
        Configured JWKSClient instance ready for key retrieval operations

    Example:
        ```python
        # Create client for Wristband JWKS endpoint
        client = create_jwks_client(JWKSClientConfig(
            jwks_uri='https://myapp.wristband.dev/api/v1/oauth2/jwks',
            cache_max_size=20,
            cache_ttl=3600000  # 1 hour TTL
        ))

        # Use in JWT validator
        public_key = client.get_signing_key('kid-abc123')
        ```

    Note:
        This function is used internally by the JWT validator factory
    """
    return JWKSClient(config)
