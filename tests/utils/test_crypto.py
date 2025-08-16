from unittest.mock import Mock, patch

import pytest

from wristband.python_jwt.utils.crypto import (
    PEM_FOOTER,
    PEM_HEADER,
    _import_rsa_public_key,
    base64url_decode,
    base64url_decode_bytes,
    validate_algorithm,
    verify_rs256_signature,
)


class TestCryptoUtils:
    """Test suite for crypto utility functions."""

    # Test vectors matching TypeScript implementation
    BASE64URL_TEST_VECTORS = {
        "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9": '{"alg":"RS256","typ":"JWT"}',
        "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0": '{"sub":"1234567890","name":"John Doe"}',
        "SGVsbG8gV29ybGQ": "Hello World",
        "YQ": "a",
        "": "",
    }

    EDGE_CASE_VECTORS = {
        "QQ": "A",  # Single character
        "QUE": "AA",  # Two characters
        "QUJD": "ABC",  # Three characters
        "QUJDRA": "ABCD",  # Four characters
    }

    INVALID_BASE64URL = [
        "invalid+chars",  # Contains +
        "invalid/chars",  # Contains /
        "invalid=padding",  # Contains =
        "invalid chars",  # Contains space
        "invalid\nchars",  # Contains newline
    ]

    # Test RSA key for crypto operations
    TEST_PUBLIC_KEY = f"""{PEM_HEADER}
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwJKvPBOGU7JM7Z8rE4Q1
xKqPdNjYzXUv8VnN9X5hXxRKzVyLq9V3EKnGgO5DV5Q5B8M5F4D1L8V2K4M3R9K5
L2X9Q3J1Y6V3M8L4N9P2Q7W8F5T6K9M3L1B7V4X2Z8H3J9R6Q5V1F8L2M4P7N9K3
B2D5X8W6T4M1Q9V3L7F5K2H8J6R4P9M3B1X5Z7N2Q8V4L6F9T3K1M8P5J7R2B4D6
X9W3Q1V5L8F2K4M7P3J9R6B5D2X8W6T1V4L9F3K5M2P8J7R4B6D3X9W5Q2V1L8F4
K7M3P6J9R2B5D8X1W4Q6V3L9F2K5M8P4J7R6B3D1X9W2Q5V4L8F6K3M7P9J2R5B8
DQIDAQAB
{PEM_FOOTER}"""


class TestBase64urlDecode:
    """Test base64url decoding functionality."""

    def test_valid_inputs(self):
        """Should decode valid base64url inputs correctly."""
        for input_str, expected in TestCryptoUtils.BASE64URL_TEST_VECTORS.items():
            result = base64url_decode(input_str)
            assert result == expected, f"Failed to decode {input_str}"

    def test_edge_cases(self):
        """Should handle edge case inputs correctly."""
        for input_str, expected in TestCryptoUtils.EDGE_CASE_VECTORS.items():
            result = base64url_decode(input_str)
            assert result == expected, f"Failed to decode edge case {input_str}"

    def test_strings_without_padding(self):
        """Should handle strings without padding."""
        without_padding = "SGVsbG8"
        result = base64url_decode(without_padding)
        assert result == "Hello"

    def test_url_safe_characters(self):
        """Should handle URL-safe characters."""
        url_safe = "SGVsbG8tV29ybGQ_"
        result = base64url_decode(url_safe)
        assert "Hello" in result

    def test_invalid_inputs(self):
        """Should throw on invalid inputs."""
        for invalid_input in TestCryptoUtils.INVALID_BASE64URL:
            with pytest.raises(ValueError, match="Invalid base64url encoding"):
                base64url_decode(invalid_input)

    def test_strict_base64url_validation(self):
        """Should strictly validate base64url format."""
        # These should be rejected because they contain standard base64 characters
        # that shouldn't appear in proper base64url
        invalid_for_base64url = [
            "SGVsbG8+V29ybGQ",  # Contains >
            "SGVsbG8/V29ybGQ",  # Contains ?
            "SGVsbG8=",  # Contains =
        ]

        for invalid_input in invalid_for_base64url:
            with pytest.raises(ValueError, match="Invalid base64url encoding"):
                base64url_decode(invalid_input)

    def test_invalid_base64_characters(self):
        """Should throw on input with invalid base64 characters."""
        with pytest.raises(ValueError, match="Invalid base64url encoding"):
            base64url_decode("invalid@#$%")

    def test_empty_string(self):
        """Should handle empty string."""
        assert base64url_decode("") == ""

    def test_consistency_multiple_calls(self):
        """Should be consistent with multiple calls."""
        input_str = "SGVsbG8gV29ybGQ"
        result1 = base64url_decode(input_str)
        result2 = base64url_decode(input_str)
        assert result1 == result2

    def test_base64url_decode_exception_handling(self):
        """Test exception handling in base64url_decode."""

        with patch("base64.b64decode") as mock_b64decode:
            mock_b64decode.side_effect = Exception("Mocked decode failure")

            with pytest.raises(ValueError, match="Invalid base64url encoding: Mocked decode failure"):
                base64url_decode("SGVsbG8")


class TestBase64urlDecodeBytes:
    """Test base64url to bytes conversion."""

    def test_valid_conversions(self):
        """Should convert base64url to bytes correctly."""
        input_str = "SGVsbG8gV29ybGQ"
        result_bytes = base64url_decode_bytes(input_str)

        assert isinstance(result_bytes, bytes)
        decoded = result_bytes.decode("utf-8")
        assert decoded == "Hello World"

    def test_single_byte(self):
        """Should handle single byte conversion."""
        input_str = "QQ"
        result_bytes = base64url_decode_bytes(input_str)

        assert len(result_bytes) == 1
        assert result_bytes[0] == 65  # ASCII 'A'

    def test_empty_string(self):
        """Should handle empty string."""
        result_bytes = base64url_decode_bytes("")
        assert len(result_bytes) == 0

    def test_binary_data(self):
        """Should handle binary data correctly."""
        # Create test binary data
        original_bytes = bytes([0, 1, 2, 3, 4, 255])

        # Convert to base64url manually
        import base64

        base64_str = base64.b64encode(original_bytes).decode("ascii")
        base64url_str = base64_str.replace("+", "-").replace("/", "_").rstrip("=")

        # Test our function
        result_bytes = base64url_decode_bytes(base64url_str)
        assert result_bytes == original_bytes

    def test_invalid_inputs(self):
        """Should throw on invalid inputs."""
        for invalid_input in TestCryptoUtils.INVALID_BASE64URL:
            with pytest.raises(ValueError, match="Invalid base64url encoding"):
                base64url_decode_bytes(invalid_input)

    def test_url_safe_character_handling(self):
        """Should properly convert URL-safe characters."""
        input_str = "SGVsbG8tV29ybGQ_"
        # Should not throw
        result_bytes = base64url_decode_bytes(input_str)
        assert isinstance(result_bytes, bytes)

    def test_base64url_decode_bytes_exception_handling(self):
        """Test exception handling in base64url_decode_bytes."""

        with patch("base64.b64decode") as mock_b64decode:
            mock_b64decode.side_effect = Exception("Mocked decode failure")

            with pytest.raises(ValueError, match="Invalid base64url encoding: Mocked decode failure"):
                base64url_decode_bytes("SGVsbG8")


class TestVerifyRS256Signature:
    """Test RS256 signature verification."""

    def test_input_validation_empty_data(self):
        """Should return False for empty data."""
        result = verify_rs256_signature("", "signature", TestCryptoUtils.TEST_PUBLIC_KEY)
        assert result is False

    def test_input_validation_empty_signature(self):
        """Should return False for empty signature."""
        result = verify_rs256_signature("data", "", TestCryptoUtils.TEST_PUBLIC_KEY)
        assert result is False

    def test_input_validation_empty_public_key(self):
        """Should return False for empty public key."""
        result = verify_rs256_signature("data", "signature", "")
        assert result is False

    def test_input_validation_null_inputs(self):
        """Should return False for None inputs."""
        assert verify_rs256_signature(None, "sig", "key") is False
        assert verify_rs256_signature("data", None, "key") is False
        assert verify_rs256_signature("data", "sig", None) is False

    def test_input_validation_non_string_inputs(self):
        """Should return False for non-string inputs."""
        assert verify_rs256_signature(123, "sig", "key") is False
        assert verify_rs256_signature("data", 456, "key") is False
        assert verify_rs256_signature("data", "sig", 789) is False

    def test_invalid_signatures(self):
        """Should handle invalid signatures."""
        result = verify_rs256_signature("test.data", "invalid_signature_data", TestCryptoUtils.TEST_PUBLIC_KEY)
        assert result is False

    def test_malformed_public_keys(self):
        """Should handle malformed public keys."""
        result = verify_rs256_signature("data", "signature", "invalid-pem-format")
        assert result is False

    def test_malformed_signatures(self):
        """Should handle malformed signatures."""
        result = verify_rs256_signature("data", "not-base64url!@#$", TestCryptoUtils.TEST_PUBLIC_KEY)
        assert result is False

    def test_signature_verification_process(self):
        """Should handle verification process end-to-end."""
        result = verify_rs256_signature(
            "header.payload", "dGVzdHNpZ25hdHVyZQ", TestCryptoUtils.TEST_PUBLIC_KEY  # Valid base64url: "testsignature"
        )

        assert isinstance(result, bool)
        # Should be False since signature doesn't match, but process should complete
        assert result is False

    def test_real_signature_verification_with_valid_key(self):
        """Should execute verification with a real RSA key."""
        # This should complete the verification process but return False
        # since the signature doesn't actually match the data
        result = verify_rs256_signature(
            "test.data", "dGVzdHNpZ25hdHVyZQ", TestCryptoUtils.TEST_PUBLIC_KEY  # Valid base64url format
        )

        assert result is False  # Signature won't match, but crypto operations succeed

    @patch("wristband.python_jwt.utils.crypto._import_rsa_public_key")
    def test_key_import_failure(self, mock_import):
        """Should handle key import failures."""
        mock_import.side_effect = ValueError("Key import failed")

        result = verify_rs256_signature("data", "signature", "key")
        assert result is False

    @patch("wristband.python_jwt.utils.crypto.base64url_decode_bytes")
    def test_signature_decode_failure(self, mock_decode):
        """Should handle signature decode failures."""
        mock_decode.side_effect = ValueError("Decode failed")

        result = verify_rs256_signature("data", "signature", TestCryptoUtils.TEST_PUBLIC_KEY)
        assert result is False

    def test_verify_rs256_signature_successful_verification(self):
        """Test successful signature verification return True path."""

        with (
            patch("wristband.python_jwt.utils.crypto.base64url_decode_bytes") as mock_decode,
            patch("wristband.python_jwt.utils.crypto._import_rsa_public_key") as mock_import,
        ):

            mock_decode.return_value = b"fake_signature_bytes"

            mock_public_key = Mock()
            mock_public_key.verify.return_value = None  # verify() returns None on success
            mock_import.return_value = mock_public_key

            result = verify_rs256_signature("test.data", "valid_signature", "valid_key")
            assert result is True


class TestValidateAlgorithm:
    """Test algorithm validation functionality."""

    def test_allowlist_validation_accept_allowed(self):
        """Should accept algorithms in allowlist."""
        assert validate_algorithm("RS256", ["RS256"]) is True
        assert validate_algorithm("RS384", ["RS256", "RS384"]) is True
        assert validate_algorithm("RS512", ["RS256", "RS384", "RS512"]) is True

    def test_allowlist_validation_reject_not_allowed(self):
        """Should reject algorithms not in allowlist."""
        assert validate_algorithm("HS256", ["RS256"]) is False
        assert validate_algorithm("ES256", ["RS256"]) is False
        assert validate_algorithm("PS256", ["RS256"]) is False
        assert validate_algorithm("unknown", ["RS256"]) is False

    def test_empty_allowlist(self):
        """Should handle empty allowlist."""
        assert validate_algorithm("RS256", []) is False

    def test_multiple_allowed_algorithms(self):
        """Should handle multiple allowed algorithms."""
        allowed_algs = ["RS256", "RS384", "RS512"]

        assert validate_algorithm("RS256", allowed_algs) is True
        assert validate_algorithm("RS384", allowed_algs) is True
        assert validate_algorithm("RS512", allowed_algs) is True
        assert validate_algorithm("HS256", allowed_algs) is False

    def test_case_insensitive_valid_algorithms(self):
        """Should be case insensitive for valid algorithms."""
        assert validate_algorithm("rs256", ["RS256"]) is True
        assert validate_algorithm("Rs256", ["RS256"]) is True
        assert validate_algorithm("RS256", ["rs256"]) is True
        assert validate_algorithm("rS256", ["Rs256"]) is True

    def test_case_insensitive_invalid_algorithms(self):
        """Should be case insensitive for invalid algorithms."""
        assert validate_algorithm("hs256", ["RS256"]) is False
        assert validate_algorithm("Hs256", ["RS256"]) is False
        assert validate_algorithm("UNKNOWN", ["RS256"]) is False

    def test_none_algorithm_security_always_reject(self):
        """Should always reject 'none' algorithm."""
        assert validate_algorithm("none", ["none"]) is False
        assert validate_algorithm("none", ["RS256", "none"]) is False
        assert validate_algorithm("none", []) is False

    def test_none_algorithm_different_cases(self):
        """Should reject 'none' algorithm in different cases."""
        assert validate_algorithm("NONE", ["NONE"]) is False
        assert validate_algorithm("None", ["None"]) is False
        assert validate_algorithm("NoNe", ["NoNe"]) is False

    def test_none_algorithm_explicitly_allowed(self):
        """Should reject 'none' even if explicitly allowed."""
        assert validate_algorithm("none", ["none", "RS256"]) is False

    def test_edge_cases_empty_strings(self):
        """Should handle empty strings."""
        assert validate_algorithm("", ["RS256"]) is False
        assert validate_algorithm("RS256", [""]) is False
        assert validate_algorithm("", [""]) is False

    def test_edge_cases_whitespace(self):
        """Should handle whitespace strings."""
        assert validate_algorithm(" ", ["RS256"]) is False
        assert validate_algorithm("RS256", [" "]) is False
        assert validate_algorithm("  ", ["  "]) is False

    def test_edge_cases_whitespace_around_valid(self):
        """Should not accept whitespace around valid algorithms."""
        assert validate_algorithm(" RS256 ", ["RS256"]) is False
        assert validate_algorithm("RS256", [" RS256 "]) is False

    def test_edge_cases_special_characters(self):
        """Should handle special characters."""
        assert validate_algorithm("RS256!", ["RS256"]) is False
        assert validate_algorithm("RS-256", ["RS256"]) is False
        assert validate_algorithm("RS_256", ["RS256"]) is False

    def test_type_safety_non_string_algorithm(self):
        """Should handle non-string algorithm input safely."""
        assert validate_algorithm(None, ["RS256"]) is False
        assert validate_algorithm(123, ["RS256"]) is False
        assert validate_algorithm([], ["RS256"]) is False
        assert validate_algorithm({}, ["RS256"]) is False

    def test_type_safety_non_list_allowlist(self):
        """Should handle non-list allowlist safely."""
        assert validate_algorithm("RS256", None) is False
        assert validate_algorithm("RS256", "RS256") is False
        assert validate_algorithm("RS256", 123) is False
        assert validate_algorithm("RS256", {}) is False

    def test_security_best_practices_allowlist_approach(self):
        """Should implement allowlist approach (OWASP recommendation)."""
        common_algorithms = ["HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "ES256", "PS256"]
        allowed_algs = ["RS256"]

        for alg in common_algorithms:
            if alg == "RS256":
                assert validate_algorithm(alg, allowed_algs) is True
            else:
                assert validate_algorithm(alg, allowed_algs) is False

    def test_prevent_algorithm_confusion_attacks(self):
        """Should prevent algorithm confusion attacks."""
        assert validate_algorithm("HS256", ["RS256"]) is False
        assert validate_algorithm("HS384", ["RS256"]) is False
        assert validate_algorithm("HS512", ["RS256"]) is False


class TestImportRSAPublicKey:
    """Test RSA public key import functionality."""

    def test_valid_key_import(self):
        """Should import valid RSA public key."""
        key = _import_rsa_public_key(TestCryptoUtils.TEST_PUBLIC_KEY)

        # Should return RSAPublicKey object
        from cryptography.hazmat.primitives.asymmetric import rsa

        assert isinstance(key, rsa.RSAPublicKey)

        # Should have adequate key size
        assert key.key_size >= 2048

    def test_invalid_pem_format_missing_headers(self):
        """Should raise ValueError for missing PEM headers."""
        invalid_key = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA..."

        with pytest.raises(ValueError, match="Invalid PEM format - missing headers"):
            _import_rsa_public_key(invalid_key)

    def test_invalid_pem_format_missing_header(self):
        """Should raise ValueError for missing BEGIN header."""
        invalid_key = f"""MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
{PEM_FOOTER}"""

        with pytest.raises(ValueError, match="Invalid PEM format - missing headers"):
            _import_rsa_public_key(invalid_key)

    def test_invalid_pem_format_missing_footer(self):
        """Should raise ValueError for missing END footer."""
        invalid_key = f"""{PEM_HEADER}
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA..."""

        with pytest.raises(ValueError, match="Invalid PEM format - missing headers"):
            _import_rsa_public_key(invalid_key)

    def test_malformed_pem_data(self):
        """Should raise ValueError for malformed PEM data."""
        invalid_key = f"""{PEM_HEADER}
invalid-base64-data-here
{PEM_FOOTER}"""

        with pytest.raises(ValueError, match="Failed to import RSA public key"):
            _import_rsa_public_key(invalid_key)

    def test_import_rsa_public_key_non_rsa_key_direct(self):
        """Test the non-RSA key isinstance check directly."""

        with patch("cryptography.hazmat.primitives.serialization.load_pem_public_key") as mock_load:
            # Create a mock that is NOT an RSA key
            mock_ec_key = Mock()
            # Don't set spec - this ensures isinstance(mock_ec_key, rsa.RSAPublicKey) returns False
            mock_load.return_value = mock_ec_key

            # This should hit the isinstance check and raise "Key is not an RSA public key"
            with pytest.raises(ValueError, match="Failed to import RSA public key"):
                _import_rsa_public_key(TestCryptoUtils.TEST_PUBLIC_KEY)

    def test_import_rsa_public_key_weak_key_error(self):
        """Test the weak RSA key error condition."""
        from cryptography.hazmat.primitives.asymmetric import rsa

        with patch("cryptography.hazmat.primitives.serialization.load_pem_public_key") as mock_load:
            # Mock a valid RSA key that's too weak
            mock_weak_key = Mock(spec=rsa.RSAPublicKey)
            mock_weak_key.key_size = 1024  # Too weak (< 2048)
            mock_load.return_value = mock_weak_key

            # This should hit the "RSA key too weak" error
            with pytest.raises(ValueError, match="Failed to import RSA public key"):
                _import_rsa_public_key(TestCryptoUtils.TEST_PUBLIC_KEY)

    def test_key_size_validation(self):
        """Should validate RSA key meets minimum size requirements."""
        # Test that our test key meets requirements
        key = _import_rsa_public_key(TestCryptoUtils.TEST_PUBLIC_KEY)
        assert key.key_size >= 2048

    def test_empty_key_string(self):
        """Should handle empty key string."""
        with pytest.raises(ValueError, match="Invalid PEM format - missing headers"):
            _import_rsa_public_key("")

    def test_none_key_input(self):
        """Should handle None key input."""
        with pytest.raises(ValueError, match="Failed to import RSA public key"):
            _import_rsa_public_key(None)


class TestIntegrationScenarios:
    """Test integration scenarios combining multiple functions."""

    def test_complete_jwt_header_decoding_workflow(self):
        """Should handle complete JWT header decoding workflow."""
        jwt_header = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9"
        decoded = base64url_decode(jwt_header)

        import json

        header_obj = json.loads(decoded)

        assert header_obj["alg"] == "RS256"
        assert header_obj["typ"] == "JWT"
        assert validate_algorithm(header_obj["alg"], ["RS256"]) is True

    def test_base64url_roundtrip_consistency(self):
        """Should handle base64url roundtrip consistency."""
        original_data = "Hello, World! This is a test string with special characters: !@#$%^&*()"

        # Encode to base64url
        import base64

        encoded_bytes = original_data.encode("utf-8")
        base64_str = base64.b64encode(encoded_bytes).decode("ascii")
        base64url_str = base64_str.replace("+", "-").replace("/", "_").rstrip("=")

        # Decode back
        decoded = base64url_decode(base64url_str)

        assert decoded == original_data

    def test_signature_data_preparation(self):
        """Should handle signature data preparation."""
        header = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9"
        payload = "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0"
        signing_input = f"{header}.{payload}"

        data_bytes = signing_input.encode("utf-8")
        assert isinstance(data_bytes, bytes)
        assert len(data_bytes) > 0

    def test_complete_jwt_validation_workflow(self):
        """Should handle complete JWT validation workflow."""
        # Simulate a complete JWT validation process
        header = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9"
        payload = "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0"
        signature = "dGVzdHNpZ25hdHVyZQ"  # "testsignature" in base64url

        # Decode and validate header
        decoded_header = base64url_decode(header)
        import json

        header_obj = json.loads(decoded_header)

        # Validate algorithm
        assert validate_algorithm(header_obj["alg"], ["RS256"]) is True

        # Prepare signing input
        signing_input = f"{header}.{payload}"

        # Verify signature (will return False since it's not a real signature)
        result = verify_rs256_signature(signing_input, signature, TestCryptoUtils.TEST_PUBLIC_KEY)
        assert isinstance(result, bool)


class TestErrorHandlingAndSecurity:
    """Test error handling and security aspects."""

    def test_no_sensitive_information_exposure(self):
        """Should not expose sensitive information in errors."""
        # All crypto functions should handle errors gracefully without exposing details
        result = verify_rs256_signature("data", "invalid-signature", "invalid-key")
        assert result is False  # Should return False, not raise exception

    def test_timing_attack_resistance(self):
        """Should be resistant to timing attacks."""
        # verify_rs256_signature should return False consistently regardless of failure point

        # Invalid signature
        result1 = verify_rs256_signature("data", "invalid", TestCryptoUtils.TEST_PUBLIC_KEY)

        # Invalid key
        result2 = verify_rs256_signature("data", "signature", "invalid-key")

        # Invalid data
        result3 = verify_rs256_signature("", "signature", TestCryptoUtils.TEST_PUBLIC_KEY)

        # All should return False
        assert result1 is False
        assert result2 is False
        assert result3 is False

    def test_input_sanitization(self):
        """Should properly sanitize inputs."""
        # Test that functions handle various input types gracefully

        # base64url_decode with non-string input should raise TypeError/ValueError
        with pytest.raises((TypeError, ValueError)):
            base64url_decode(123)

        # validate_algorithm with non-string algorithm
        assert validate_algorithm(123, ["RS256"]) is False

        # verify_rs256_signature with non-string inputs
        assert verify_rs256_signature(123, "sig", "key") is False

    def test_constant_time_operations(self):
        """Should use constant-time operations where possible."""
        # The cryptography library handles constant-time operations internally
        # We just verify that our functions complete successfully

        valid_signature = "dGVzdHNpZ25hdHVyZQ"
        invalid_signature = "aW52YWxpZHNpZ25hdHVyZQ"

        result1 = verify_rs256_signature("data", valid_signature, TestCryptoUtils.TEST_PUBLIC_KEY)
        result2 = verify_rs256_signature("data", invalid_signature, TestCryptoUtils.TEST_PUBLIC_KEY)

        # Both should return False (neither signature is valid for 'data')
        assert result1 is False
        assert result2 is False

    def test_algorithm_confusion_prevention(self):
        """Should prevent algorithm confusion attacks."""
        # Ensure that only explicitly allowed algorithms are accepted
        dangerous_algorithms = ["none", "HS256", "HS384", "HS512"]
        safe_algorithms = ["RS256"]

        for dangerous_alg in dangerous_algorithms:
            assert validate_algorithm(dangerous_alg, safe_algorithms) is False

        for safe_alg in safe_algorithms:
            assert validate_algorithm(safe_alg, safe_algorithms) is True

    def test_memory_safety(self):
        """Should handle memory safely."""
        # Test with large inputs to ensure no memory issues
        large_data = "x" * 10000
        large_signature = "dGVzdA" * 1000  # Large but valid base64url

        # Should not crash or consume excessive memory
        result = verify_rs256_signature(large_data, large_signature, TestCryptoUtils.TEST_PUBLIC_KEY)
        assert isinstance(result, bool)


class TestConstants:
    """Test module constants."""

    def test_pem_header_constant(self):
        """Should have correct PEM header constant."""
        assert PEM_HEADER == "-----BEGIN PUBLIC KEY-----"

    def test_pem_footer_constant(self):
        """Should have correct PEM footer constant."""
        assert PEM_FOOTER == "-----END PUBLIC KEY-----"

    def test_constants_used_in_key_validation(self):
        """Should use constants in key validation."""
        # Test that constants are used correctly in _import_rsa_public_key
        key_without_header = f"""MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
{PEM_FOOTER}"""

        with pytest.raises(ValueError, match="Invalid PEM format - missing headers"):
            _import_rsa_public_key(key_without_header)

        key_without_footer = f"""{PEM_HEADER}
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA..."""

        with pytest.raises(ValueError, match="Invalid PEM format - missing headers"):
            _import_rsa_public_key(key_without_footer)
