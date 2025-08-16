"""
Crypto utility functions for JWT validation using standard Python libraries.

This module provides framework-agnostic cryptographic utilities for JWT token validation
using the cryptography library and standard Python APIs. Compatible with Python 3.9+.

All functions follow OWASP security recommendations and use only secure, standardized
cryptographic primitives to prevent common JWT vulnerabilities.
"""

import base64
from typing import List

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

PEM_HEADER = "-----BEGIN PUBLIC KEY-----"
PEM_FOOTER = "-----END PUBLIC KEY-----"


def base64url_decode(data: str) -> str:
    """
    Decode a base64url-encoded string to a regular UTF-8 string.

    Base64url encoding is used in JWTs as it's URL-safe (no padding, uses - and _
    instead of + and /). This method converts base64url back to standard base64
    by adding padding and replacing URL-safe characters, then decodes to UTF-8.

    Args:
        data: The base64url-encoded string to decode

    Returns:
        The decoded UTF-8 string

    Example:
        ```python
        encoded = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9"
        decoded = base64url_decode(encoded)
        print(decoded)  # '{"alg":"RS256","typ":"JWT"}'
        ```

    Raises:
        ValueError: If the input contains invalid base64 characters
    """
    if "+" in data or "/" in data or "=" in data:
        raise ValueError("Invalid base64url encoding: contains standard base64 characters")

    if not all(c.isalnum() or c in "-_" for c in data):
        raise ValueError("Invalid base64url encoding: contains invalid characters")

    # Add padding if needed
    padding = 4 - (len(data) % 4)
    if padding != 4:
        data += "=" * padding

    # Replace URL-safe characters with standard base64 characters
    data = data.replace("-", "+").replace("_", "/")

    try:
        return base64.b64decode(data).decode("utf-8")
    except Exception as e:
        raise ValueError(f"Invalid base64url encoding: {e}")


def base64url_decode_bytes(data: str) -> bytes:
    """
    Convert a base64url-encoded string directly to bytes.

    This is more efficient than decoding to string first when the end goal
    is binary data for cryptographic operations. Used primarily for converting
    JWT signatures from base64url format to bytes for signature verification.

    Args:
        data: The base64url-encoded string to convert

    Returns:
        bytes containing the decoded binary data

    Example:
        ```python
        signature = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        signature_bytes = base64url_decode_bytes(signature)
        # Use signature_bytes with RSA verification
        ```

    Raises:
        ValueError: If the input contains invalid base64 characters
    """
    if "+" in data or "/" in data or "=" in data:
        raise ValueError("Invalid base64url encoding: contains standard base64 characters")

    if not all(c.isalnum() or c in "-_" for c in data):
        raise ValueError("Invalid base64url encoding: contains invalid characters")

    # Add padding if needed
    padding = 4 - (len(data) % 4)
    if padding != 4:
        data += "=" * padding

    # Replace URL-safe characters with standard base64 characters
    data = data.replace("-", "+").replace("_", "/")

    try:
        return base64.b64decode(data)
    except Exception as e:
        raise ValueError(f"Invalid base64url encoding: {e}")


def verify_rs256_signature(data: str, signature: str, public_key_pem: str) -> bool:
    """
    Verify an RS256 JWT signature using the cryptography library.

    Implements OWASP-compliant JWT signature verification using RSASSA-PKCS1-v1_5
    with SHA-256.

    Security features:
    - Uses cryptography library for constant-time operations
    - Validates input parameters to prevent timing attacks
    - Implements OWASP-recommended RSASSA-PKCS1-v1_5 + SHA-256
    - Graceful error handling without information leakage

    Args:
        data: The JWT header and payload joined with a dot (e.g., "header.payload")
        signature: The base64url-encoded signature to verify
        public_key_pem: The RSA public key in PEM format for verification

    Returns:
        True if signature is valid; False otherwise

    Example:
        ```python
        header_payload = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0"
        signature = "EkN-DOsnsuRjRO6BxXemmJDm3HbxrbRzXglbN2S4sOkopdU4IsDxTI...."
        public_key = "-----BEGIN PUBLIC KEY-----\\n..."

        is_valid = verify_rs256_signature(header_payload, signature, public_key)
        if is_valid:
            print("Signature verified successfully")
        else:
            print("Invalid signature")
        ```
    """
    try:
        # Check for null/empty inputs
        if not data or not signature or not public_key_pem:
            return False

        # Explicit type validation to prevent type confusion attacks
        if not all(isinstance(x, str) for x in [data, signature, public_key_pem]):
            return False

        # Convert base64url signature to bytes
        signature_bytes = base64url_decode_bytes(signature)

        # Convert data string to bytes
        data_bytes = data.encode("utf-8")

        # Parse PEM public key
        public_key = _import_rsa_public_key(public_key_pem)

        # Verify signature using cryptography library with RS256 (RSASSA-PKCS1-v1_5 + SHA-256)
        # Will raise Exception if verification fails.
        public_key.verify(signature_bytes, data_bytes, padding.PKCS1v15(), hashes.SHA256())

        return True

    except Exception:
        return False


def validate_algorithm(algorithm: str, allowed_algorithms: List[str]) -> bool:
    """
    Validate JWT signing algorithms against an allowlist to prevent algorithm confusion attacks.

    Implements OWASP-recommended algorithm validation using an allowlist approach rather than
    a denylist. This prevents various JWT vulnerabilities including:
    - Algorithm confusion attacks (RS256 vs HS256)
    - "none" algorithm bypass attacks
    - Case sensitivity exploitation

    The validation is case-insensitive to handle variations in algorithm naming while
    maintaining security through explicit allowlisting.

    Args:
        algorithm: The algorithm claim from the JWT header (e.g., "RS256", "HS256")
        allowed_algorithms: List of permitted algorithm names for validation

    Returns:
        True if the algorithm is in the allowlist and secure; False otherwise

    Example:
        ```python
        # Secure validation - only allow RS256
        is_valid = validate_algorithm("RS256", ["RS256"])
        print(is_valid)  # True

        # Prevent algorithm confusion attack
        is_valid2 = validate_algorithm("HS256", ["RS256"])
        print(is_valid2)  # False

        # Prevent "none" algorithm bypass
        is_valid3 = validate_algorithm("none", ["RS256"])
        print(is_valid3)  # False

        # Case insensitive validation
        is_valid4 = validate_algorithm("rs256", ["RS256"])
        print(is_valid4)  # True
        ```

    Security:
    - Uses allowlist approach
    - Explicitly rejects "none" algorithm
    - Case-insensitive to prevent bypass attempts
    - No regex or complex parsing to avoid ReDoS attacks
    """
    if not isinstance(algorithm, str) or not algorithm.strip():
        return False

    if not isinstance(allowed_algorithms, list):
        return False

    normalized_alg = algorithm.lower()
    normalized_allowed = [alg.lower() for alg in allowed_algorithms if alg and alg.strip()]

    if normalized_alg == "none":
        return False

    return normalized_alg in normalized_allowed


def _import_rsa_public_key(pem_key: str) -> rsa.RSAPublicKey:
    """
    Import an RSA public key from PEM format using the cryptography library.

    Converts a PEM-encoded RSA public key into a cryptography RSAPublicKey object
    suitable for use with signature verification operations. Implements secure key
    handling practices recommended by OWASP.

    The function expects standard PEM format with proper headers and base64-encoded
    DER data. It performs validation to ensure the key is properly formatted before
    attempting import operations.

    Args:
        pem_key: RSA public key in PEM format with proper headers

    Returns:
        RSAPublicKey object configured for RS256 verification

    Example:
        ```python
        pem_key = '''-----BEGIN PUBLIC KEY-----
        MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4f5wg5l2hKsTeNem/V41
        fGnJm6gOdrj8ym3rFkEjWT2btf02uSxZ8gktFfT0CvQKOGaKN8JW2P1MvcKZJdFC
        ...
        -----END PUBLIC KEY-----'''

        crypto_key = _import_rsa_public_key(pem_key)
        # Use crypto_key with RSA verification
        ```

    Raises:
        ValueError: If PEM format is invalid, missing headers, key import fails,
                   or RSA key is below 2048-bit minimum security requirement

    Note:
        This function is used internally by verify_rs256_signature
    """
    try:
        # Validate PEM format
        if PEM_HEADER not in pem_key or PEM_FOOTER not in pem_key:
            raise ValueError("Invalid PEM format - missing headers")

        # Load the public key using cryptography library
        public_key = serialization.load_pem_public_key(pem_key.encode("utf-8"))

        # Ensure it's an RSA key
        if not isinstance(public_key, rsa.RSAPublicKey):
            raise ValueError("Key is not an RSA public key")

        # Validate RSA key strength (minimum 2048 bits)
        key_size = public_key.key_size
        if key_size < 2048:
            raise ValueError(f"RSA key too weak: {key_size} bits. Minimum 2048 bits required.")

        return public_key

    except Exception as e:
        raise ValueError(f"Failed to import RSA public key: {e}")
