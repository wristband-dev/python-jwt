import concurrent.futures
import re
from unittest.mock import Mock, patch

import httpx
import pytest

from wristband.python_jwt.jwks_client import JWKS_MAX_ATTEMPTS, JWKS_RETRY_DELAY_MS, JWKSClient, create_jwks_client
from wristband.python_jwt.models import JWKSClientConfig, JWKSKey, JWKSResponse


def create_2048_bit_modulus():
    """Create a base64url-encoded 2048-bit RSA modulus."""
    import base64

    bytes_data = b"\x00" + b"A" * 255
    return base64.b64encode(bytes_data).decode("ascii").replace("+", "-").replace("/", "_").replace("=", "")


def create_1024_bit_modulus():
    """Create a base64url-encoded 1024-bit RSA modulus."""
    import base64

    bytes_data = b"\x00" + b"A" * 127
    return base64.b64encode(bytes_data).decode("ascii").replace("+", "-").replace("/", "_").replace("=", "")


VALID_JWK_DICT = {"kty": "RSA", "kid": "test-key-id", "use": "sig", "n": create_2048_bit_modulus(), "e": "AQAB"}
WEAK_JWK_DICT = {"kty": "RSA", "kid": "weak-key-id", "use": "sig", "n": create_1024_bit_modulus(), "e": "AQAB"}
VALID_JWKS_RESPONSE_DICT = {
    "keys": [
        VALID_JWK_DICT,
        {"kty": "RSA", "kid": "another-key-id", "use": "sig", "n": create_2048_bit_modulus(), "e": "AQAB"},
    ]
}
VALID_JWK = JWKSKey(VALID_JWK_DICT)
WEAK_JWK = JWKSKey(WEAK_JWK_DICT)
VALID_JWKS_RESPONSE = JWKSResponse(VALID_JWKS_RESPONSE_DICT)


class TestJWKSClientConstructor:
    def test_constructor_with_null_config(self):
        """Should throw when config is None."""
        with pytest.raises(ValueError, match="A valid JWKS URI is required"):
            JWKSClient(None)

    def test_constructor_with_empty_jwks_uri(self):
        """Should throw when jwksUri is empty string."""
        config = JWKSClientConfig(jwks_uri="")
        with pytest.raises(ValueError, match="A valid JWKS URI is required"):
            JWKSClient(config)

    def test_constructor_with_whitespace_jwks_uri(self):
        """Should throw when jwksUri is only whitespace."""
        config = JWKSClientConfig(jwks_uri="   ")
        with pytest.raises(ValueError, match="A valid JWKS URI is required"):
            JWKSClient(config)

    def test_constructor_with_invalid_cache_max_size(self):
        """Should create client with valid configuration."""
        config = JWKSClientConfig(jwks_uri="https://test.example.com/jwks", cache_max_size=-1)
        with pytest.raises(ValueError, match="max_size must be a positive integer"):
            JWKSClient(config)

    def test_constructor_with_invalid_cache_ttl(self):
        """Should create client with valid configuration."""
        config = JWKSClientConfig(jwks_uri="https://test.example.com/jwks", cache_ttl=-1)
        with pytest.raises(ValueError, match="ttl must be a positive integer \\(if specified\\)"):
            JWKSClient(config)

    def test_constructor_with_valid_default_config(self):
        """Should create client with valid configuration."""
        config = JWKSClientConfig(
            jwks_uri="https://test.example.com/jwks",
        )
        client = JWKSClient(config)
        assert client._jwks_uri == "https://test.example.com/jwks"
        assert client._cache._max_size == 20
        assert client._cache._ttl is None
        assert client.get_cache_stats()["size"] == 0
        assert client.get_cache_stats()["max_size"] == 20

    def test_constructor_with_valid_explicit_cache_size(self):
        """Should create client with valid configuration."""
        config = JWKSClientConfig(jwks_uri="https://test.example.com/jwks", cache_max_size=12)
        client = JWKSClient(config)
        assert client._jwks_uri == "https://test.example.com/jwks"
        assert client._cache._max_size == 12
        assert client._cache._ttl is None
        assert client.get_cache_stats()["size"] == 0
        assert client.get_cache_stats()["max_size"] == 12

    def test_constructor_with_valid_explicit_ttl(self):
        """Should create client with valid configuration."""
        config = JWKSClientConfig(
            jwks_uri="https://test.example.com/jwks",
            cache_max_size=50,
            cache_ttl=3600000,
        )
        client = JWKSClient(config)
        assert client._jwks_uri == "https://test.example.com/jwks"
        assert client._cache._max_size == 50
        assert client._cache._ttl == 3600000
        assert client.get_cache_stats()["size"] == 0
        assert client.get_cache_stats()["max_size"] == 50


class TestJWKSClientFactoryFunction:
    def test_create_client_with_correct_configuration(self):
        """Should create client with correct configuration."""
        config = JWKSClientConfig(jwks_uri="https://test.example.com/jwks", cache_max_size=25, cache_ttl=7200000)

        client = create_jwks_client(config)
        assert client._jwks_uri == "https://test.example.com/jwks"
        assert client._cache._max_size == 25
        assert client._cache._ttl == 7200000
        assert client.get_cache_stats()["size"] == 0
        assert client.get_cache_stats()["max_size"] == 25

    def test_create_client_with_minimal_configuration(self):
        """Should create client with minimal configuration."""
        config = JWKSClientConfig(jwks_uri="https://test.example.com/jwks")

        client = create_jwks_client(config)
        assert client._cache._max_size == 20
        assert client._cache._ttl is None
        assert client.get_cache_stats()["size"] == 0
        assert client.get_cache_stats()["max_size"] == 20


class TestJWKSClientConstants:
    def test_retry_delay_constant(self):
        """Should have correct retry delay constant."""
        assert JWKS_RETRY_DELAY_MS == 100

    def test_max_attempts_constant(self):
        """Should have correct max attempts constant."""
        assert JWKS_MAX_ATTEMPTS == 3


class TestJWKSClientGetSigningKey:
    @pytest.fixture(autouse=True)
    def setup_client(self):
        """Setup client before each test."""
        config = JWKSClientConfig(jwks_uri="https://test.example.com/jwks", cache_max_size=10)
        self.client = JWKSClient(config)

    def test_successful_key_retrieval(self):
        """Should fetch and return a valid signing key."""

        with patch("httpx.Client") as mock_client_class:
            mock_client = Mock()
            mock_client.__enter__ = Mock(return_value=mock_client)
            mock_client.__exit__ = Mock(return_value=None)
            mock_client_class.return_value = mock_client

            mock_response = Mock()
            mock_response.raise_for_status.return_value = None
            mock_response.json.return_value = VALID_JWKS_RESPONSE_DICT
            mock_client.get.return_value = mock_response
            mock_client_class.return_value = mock_client

            key = self.client.get_signing_key("test-key-id")

            assert re.match(r"^-----BEGIN PUBLIC KEY-----", key)
            assert re.search(r"-----END PUBLIC KEY-----$", key)
            mock_client.get.assert_called_once_with("https://test.example.com/jwks")

    def test_cached_key_on_subsequent_requests(self):
        """Should return cached key on subsequent requests."""
        config = JWKSClientConfig(jwks_uri="https://test.example.com/jwks")
        client = JWKSClient(config)

        with patch("httpx.Client") as mock_client_class:
            mock_client = Mock()
            mock_client.__enter__ = Mock(return_value=mock_client)
            mock_client.__exit__ = Mock(return_value=None)
            mock_client_class.return_value = mock_client

            mock_response = Mock()
            mock_response.raise_for_status.return_value = None
            mock_response.json.return_value = VALID_JWKS_RESPONSE_DICT
            mock_client.get.return_value = mock_response

            # First call - should fetch
            key1 = client.get_signing_key("test-key-id")

            # Second call - should use cache
            key2 = client.get_signing_key("test-key-id")

            assert key1 == key2
            assert mock_client.get.call_count == 1
            assert client.get_cache_stats()["size"] == 1

    def test_should_handle_multiple_different_keys(self):
        """Should handle multiple different keys with separate cache entries."""
        config = JWKSClientConfig(jwks_uri="https://test.example.com/jwks")
        client = JWKSClient(config)

        with patch("httpx.Client") as mock_client_class:
            mock_client = Mock()
            mock_client.__enter__ = Mock(return_value=mock_client)
            mock_client.__exit__ = Mock(return_value=None)
            mock_client_class.return_value = mock_client

            mock_response = Mock()
            mock_response.raise_for_status.return_value = None
            mock_response.json.return_value = VALID_JWKS_RESPONSE_DICT
            mock_client.get.return_value = mock_response

            # First key fetch
            key1 = client.get_signing_key("test-key-id")

            # Second key fetch (different key ID)
            key2 = client.get_signing_key("another-key-id")

            # Both should be valid PEM keys
            assert re.match(r"^-----BEGIN PUBLIC KEY-----", key1)
            assert re.match(r"^-----BEGIN PUBLIC KEY-----", key2)

            # Different keys require separate fetches (no cache hit for different key IDs)
            assert mock_client.get.call_count == 2

            # Two separate cache entries
            assert client.get_cache_stats()["size"] == 2

    def test_key_not_found_error(self):
        """Should throw when key ID is not found."""
        config = JWKSClientConfig(jwks_uri="https://test.example.com/jwks")
        client = JWKSClient(config)

        with patch("httpx.Client") as mock_client_class:
            mock_client = Mock()
            mock_client.__enter__ = Mock(return_value=mock_client)
            mock_client.__exit__ = Mock(return_value=None)
            mock_client_class.return_value = mock_client

            mock_response = Mock()
            mock_response.raise_for_status.return_value = None
            mock_response.json.return_value = VALID_JWKS_RESPONSE_DICT
            mock_client.get.return_value = mock_response
            mock_client_class.return_value = mock_client

            with pytest.raises(ValueError, match="Unable to find a signing key that matches 'nonexistent-key-id'"):
                client.get_signing_key("nonexistent-key-id")

    def test_non_rsa_key_error(self):
        """Should throw when key is not RSA."""
        config = JWKSClientConfig(jwks_uri="https://test.example.com/jwks")
        client = JWKSClient(config)

        ec_jwks = {"keys": [{"kty": "EC", "kid": "ec-key-id", "crv": "P-256"}]}

        with patch("httpx.Client") as mock_client_class:
            mock_client = Mock()
            mock_client.__enter__ = Mock(return_value=mock_client)
            mock_client.__exit__ = Mock(return_value=None)
            mock_client_class.return_value = mock_client

            mock_response = Mock()
            mock_response.raise_for_status.return_value = None
            mock_response.json.return_value = ec_jwks
            mock_client.get.return_value = mock_response
            mock_client_class.return_value = mock_client

            with pytest.raises(ValueError, match="Only RSA keys are supported"):
                client.get_signing_key("ec-key-id")

    def test_weak_rsa_key_error(self):
        """Should throw when RSA key is too weak."""
        config = JWKSClientConfig(jwks_uri="https://test.example.com/jwks")
        client = JWKSClient(config)

        weak_jwks = {"keys": [WEAK_JWK_DICT]}

        with patch("httpx.Client") as mock_client_class:
            mock_client = Mock()
            mock_client.__enter__ = Mock(return_value=mock_client)
            mock_client.__exit__ = Mock(return_value=None)
            mock_client_class.return_value = mock_client

            mock_response = Mock()
            mock_response.raise_for_status.return_value = None
            mock_response.json.return_value = weak_jwks
            mock_client.get.return_value = mock_response
            mock_client_class.return_value = mock_client

            with pytest.raises(ValueError, match="RSA key too weak"):
                client.get_signing_key("weak-key-id")

    def test_empty_key_set(self):
        """Should handle empty key set."""
        config = JWKSClientConfig(jwks_uri="https://test.example.com/jwks")
        client = JWKSClient(config)

        with patch("httpx.Client") as mock_client_class:
            mock_client = Mock()
            mock_client.__enter__ = Mock(return_value=mock_client)
            mock_client.__exit__ = Mock(return_value=None)
            mock_client_class.return_value = mock_client

            mock_response = Mock()
            mock_response.raise_for_status.return_value = None
            mock_response.json.return_value = {"keys": []}
            mock_client.get.return_value = mock_response
            mock_client_class.return_value = mock_client

            with pytest.raises(ValueError, match="Unable to find a signing key that matches 'any-key-id'"):
                client.get_signing_key("any-key-id")

    def test_should_throw_when_jwk_has_empty_required_parameters(self):
        """Should throw when JWK has empty required parameters."""
        config = JWKSClientConfig(jwks_uri="https://test.example.com/jwks")
        client = JWKSClient(config)

        # Create JWKS with key having empty/None parameters (keys exist but are falsy)
        invalid_jwks = {
            "keys": [
                {
                    "kty": "RSA",
                    "kid": "invalid-key-id",
                    "n": "",  # Empty string (falsy)
                    "e": "",  # Empty string (falsy)
                }
            ]
        }

        with patch("httpx.Client") as mock_client_class:
            mock_client = Mock()
            mock_client.__enter__ = Mock(return_value=mock_client)
            mock_client.__exit__ = Mock(return_value=None)
            mock_client_class.return_value = mock_client

            mock_response = Mock()
            mock_response.raise_for_status.return_value = None
            mock_response.json.return_value = invalid_jwks
            mock_client.get.return_value = mock_response

            # This should reach the validation logic: if not jwk.n or not jwk.e:
            with pytest.raises(ValueError, match="Invalid JWK: missing n or e parameters"):
                client.get_signing_key("invalid-key-id")

    def test_should_throw_when_jwk_has_none_parameters(self):
        """Should throw when JWK has None required parameters."""
        config = JWKSClientConfig(jwks_uri="https://test.example.com/jwks")
        client = JWKSClient(config)

        # Create JWKS with key having None parameters (keys exist but are None)
        invalid_jwks = {
            "keys": [{"kty": "RSA", "kid": "invalid-key-id", "n": None, "e": None}]  # None (falsy)  # None (falsy)
        }

        with patch("httpx.Client") as mock_client_class:
            mock_client = Mock()
            mock_client.__enter__ = Mock(return_value=mock_client)
            mock_client.__exit__ = Mock(return_value=None)
            mock_client_class.return_value = mock_client

            mock_response = Mock()
            mock_response.raise_for_status.return_value = None
            mock_response.json.return_value = invalid_jwks
            mock_client.get.return_value = mock_response

            # This should reach the validation logic: if not jwk.n or not jwk.e:
            with pytest.raises(ValueError, match="Invalid JWK: missing n or e parameters"):
                client.get_signing_key("invalid-key-id")

    def test_should_throw_when_jwk_missing_required_parameters(self):
        """Should throw when JWK is completely missing required parameters."""
        config = JWKSClientConfig(jwks_uri="https://test.example.com/jwks")
        client = JWKSClient(config)

        # Create JWKS with invalid key missing 'n' and 'e' parameters entirely
        invalid_jwks = {
            "keys": [
                {
                    "kty": "RSA",
                    "kid": "invalid-key-id",
                    # Missing 'n' and 'e' parameters entirely
                }
            ]
        }

        with patch("httpx.Client") as mock_client_class:
            mock_client = Mock()
            mock_client.__enter__ = Mock(return_value=mock_client)
            mock_client.__exit__ = Mock(return_value=None)
            mock_client_class.return_value = mock_client

            mock_response = Mock()
            mock_response.raise_for_status.return_value = None
            mock_response.json.return_value = invalid_jwks
            mock_client.get.return_value = mock_response

            # This hits KeyError when accessing jwk.n property (before validation logic)
            with pytest.raises(KeyError):
                client.get_signing_key("invalid-key-id")


class TestJWKSClientNetworkRetry:
    def test_retry_on_http_error_and_succeed(self):
        """Should retry on HTTP error response and eventually succeed."""
        config = JWKSClientConfig(jwks_uri="https://test.example.com/jwks")
        client = JWKSClient(config)

        with patch("httpx.Client") as mock_client_class, patch("time.sleep") as mock_sleep:

            mock_client = Mock()
            mock_client.__enter__ = Mock(return_value=mock_client)
            mock_client.__exit__ = Mock(return_value=None)
            mock_client_class.return_value = mock_client

            # First two attempts fail, third succeeds
            error_response1 = Mock()
            error_response1.raise_for_status.side_effect = httpx.HTTPStatusError(
                "500 Internal Server Error", request=Mock(), response=Mock()
            )

            error_response2 = Mock()
            error_response2.raise_for_status.side_effect = httpx.HTTPStatusError(
                "500 Internal Server Error", request=Mock(), response=Mock()
            )

            success_response = Mock()
            success_response.raise_for_status.return_value = None
            success_response.json.return_value = VALID_JWKS_RESPONSE_DICT

            mock_client.get.side_effect = [error_response1, error_response2, success_response]

            key = client.get_signing_key("test-key-id")
            assert key.startswith("-----BEGIN PUBLIC KEY-----")
            assert mock_client.get.call_count == 3
            assert mock_sleep.call_count == 2

    def test_fail_after_max_retry_attempts(self):
        """Should fail after all retry attempts are exhausted."""
        config = JWKSClientConfig(jwks_uri="https://test.example.com/jwks")
        client = JWKSClient(config)

        with patch("httpx.Client") as mock_client_class, patch("time.sleep") as mock_sleep:

            mock_client = Mock()
            mock_client.__enter__ = Mock(return_value=mock_client)
            mock_client.__exit__ = Mock(return_value=None)
            mock_client_class.return_value = mock_client

            mock_client.get.side_effect = [
                Exception("Network error"),
                Exception("Network error"),
                Exception("Network error"),
            ]

            with pytest.raises(ValueError, match="Failed to fetch JWKS after 3 attempts: Network error"):
                client.get_signing_key("test-key-id")

            assert mock_client.get.call_count == 3
            assert mock_sleep.call_count == 2


class TestJWKSClientCacheManagement:
    def test_clear_cached_keys(self):
        """Should clear all cached keys."""
        config = JWKSClientConfig(jwks_uri="https://test.example.com/jwks", cache_max_size=3)
        client = JWKSClient(config)

        with patch("httpx.Client") as mock_client_class:
            mock_client = Mock()
            mock_client.__enter__ = Mock(return_value=mock_client)
            mock_client.__exit__ = Mock(return_value=None)
            mock_client_class.return_value = mock_client

            mock_response = Mock()
            mock_response.raise_for_status.return_value = None
            mock_response.json.return_value = VALID_JWKS_RESPONSE_DICT
            mock_client.get.return_value = mock_response
            mock_client_class.return_value = mock_client

            client.get_signing_key("test-key-id")
            client.get_signing_key("another-key-id")

            assert client.get_cache_stats()["size"] == 2

            client.clear()
            assert client.get_cache_stats()["size"] == 0

    def test_accurate_cache_statistics(self):
        """Should provide accurate cache statistics."""
        config = JWKSClientConfig(jwks_uri="https://test.example.com/jwks", cache_max_size=3)
        client = JWKSClient(config)

        stats1 = client.get_cache_stats()
        assert stats1["size"] == 0
        assert stats1["max_size"] == 3

        with patch("httpx.Client") as mock_client_class:
            mock_client = Mock()
            mock_client.__enter__ = Mock(return_value=mock_client)
            mock_client.__exit__ = Mock(return_value=None)
            mock_client_class.return_value = mock_client

            mock_response = Mock()
            mock_response.raise_for_status.return_value = None
            mock_response.json.return_value = VALID_JWKS_RESPONSE_DICT
            mock_client.get.return_value = mock_response
            mock_client_class.return_value = mock_client

            client.get_signing_key("test-key-id")

            stats2 = client.get_cache_stats()
            assert stats2["size"] == 1
            assert stats2["max_size"] == 3


class TestJWKSClientConcurrentRequests:
    @pytest.fixture(autouse=True)
    def setup_client(self):
        """Setup client before each test."""
        config = JWKSClientConfig(jwks_uri="https://test.example.com/jwks", cache_max_size=10)
        self.client = JWKSClient(config)

    def test_should_handle_concurrent_requests_for_same_key(self):
        """Should handle concurrent requests for same key."""
        with patch("httpx.Client") as mock_client_class:
            mock_client = Mock()
            mock_client.__enter__ = Mock(return_value=mock_client)
            mock_client.__exit__ = Mock(return_value=None)
            mock_client_class.return_value = mock_client

            mock_response = Mock()
            mock_response.raise_for_status.return_value = None
            mock_response.json.return_value = VALID_JWKS_RESPONSE_DICT
            mock_client.get.return_value = mock_response

            # Make multiple concurrent requests for the same key using ThreadPoolExecutor
            with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                futures = [executor.submit(self.client.get_signing_key, "test-key-id") for _ in range(5)]
                keys = [future.result() for future in concurrent.futures.as_completed(futures)]

            # All should return the same key
            assert all(key == keys[0] for key in keys)

            # Should only have made one network request due to caching
            # Note: This test might be flaky due to timing, but generally should work
            assert self.client.get_cache_stats()["size"] == 1

    def test_should_handle_concurrent_requests_for_different_keys(self):
        """Should handle concurrent requests for different keys."""
        with patch("httpx.Client") as mock_client_class:
            mock_client = Mock()
            mock_client.__enter__ = Mock(return_value=mock_client)
            mock_client.__exit__ = Mock(return_value=None)
            mock_client_class.return_value = mock_client

            mock_response = Mock()
            mock_response.raise_for_status.return_value = None
            mock_response.json.return_value = VALID_JWKS_RESPONSE_DICT
            mock_client.get.return_value = mock_response

            # Make concurrent requests for different keys using ThreadPoolExecutor
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
                future1 = executor.submit(self.client.get_signing_key, "test-key-id")
                future2 = executor.submit(self.client.get_signing_key, "another-key-id")

                key1 = future1.result()
                key2 = future2.result()

            # Both keys exist (they might be the same PEM if moduli are identical)
            assert re.match(r"^-----BEGIN PUBLIC KEY-----", key1)
            assert re.match(r"^-----BEGIN PUBLIC KEY-----", key2)
            assert self.client.get_cache_stats()["size"] == 2  # Different cache entries by kid

    def test_concurrent_requests_with_cache_race_condition(self):
        """Test concurrent requests with potential cache race conditions."""
        # This test verifies that concurrent requests don't cause cache corruption
        with patch("httpx.Client") as mock_client_class:
            mock_client = Mock()
            mock_client.__enter__ = Mock(return_value=mock_client)
            mock_client.__exit__ = Mock(return_value=None)
            mock_client_class.return_value = mock_client

            mock_response = Mock()
            mock_response.raise_for_status.return_value = None
            mock_response.json.return_value = VALID_JWKS_RESPONSE_DICT
            mock_client.get.return_value = mock_response

            # Mix of same and different key requests
            key_ids = ["test-key-id", "another-key-id", "test-key-id", "another-key-id", "test-key-id"]

            with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                futures = [executor.submit(self.client.get_signing_key, kid) for kid in key_ids]
                keys = [future.result() for future in concurrent.futures.as_completed(futures)]

            # All keys should be valid PEM format
            for key in keys:
                assert re.match(r"^-----BEGIN PUBLIC KEY-----", key)

            # Should have 2 cache entries (for the 2 unique key IDs)
            assert self.client.get_cache_stats()["size"] == 2


class TestJWKSClientPEMFormattingEdgeCases:
    @pytest.fixture(autouse=True)
    def setup_client(self):
        """Setup client before each test."""
        config = JWKSClientConfig(jwks_uri="https://test.example.com/jwks", cache_max_size=10)
        self.client = JWKSClient(config)

    def test_should_handle_malformed_base64_during_pem_formatting(self):
        """Should handle malformed base64 during PEM formatting."""
        # Create JWKS with malformed base64 data that will fail during decoding
        malformed_jwks = {
            "keys": [
                {
                    "kty": "RSA",
                    "kid": "malformed-key",
                    "n": "invalid-base64-data!!!",  # Invalid base64 that will cause decoding to fail
                    "e": "AQAB",
                }
            ]
        }

        with patch("httpx.Client") as mock_client_class:
            mock_client = Mock()
            mock_client.__enter__ = Mock(return_value=mock_client)
            mock_client.__exit__ = Mock(return_value=None)
            mock_client_class.return_value = mock_client

            mock_response = Mock()
            mock_response.raise_for_status.return_value = None
            mock_response.json.return_value = malformed_jwks
            mock_client.get.return_value = mock_response

            # Should throw during base64 decoding due to invalid characters
            with pytest.raises(ValueError, match="Invalid base64url encoding: contains invalid characters"):
                self.client.get_signing_key("malformed-key")

    def test_should_handle_cryptography_library_failure(self):
        """Should handle cryptography library failure during PEM conversion."""
        # Mock the RSA key creation to fail
        with (
            patch("httpx.Client") as mock_client_class,
            patch("cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicNumbers") as mock_rsa_numbers,
        ):

            # Setup HTTP mock
            mock_client = Mock()
            mock_client.__enter__ = Mock(return_value=mock_client)
            mock_client.__exit__ = Mock(return_value=None)
            mock_client_class.return_value = mock_client

            mock_response = Mock()
            mock_response.raise_for_status.return_value = None
            mock_response.json.return_value = VALID_JWKS_RESPONSE_DICT
            mock_client.get.return_value = mock_response

            # Mock RSA key creation to raise an exception
            mock_rsa_numbers.side_effect = Exception("RSA key creation failed")

            # Should throw during PEM conversion due to cryptography library failure
            with pytest.raises(ValueError, match="Failed to convert JWK to PEM"):
                self.client.get_signing_key("test-key-id")

    def test_should_handle_invalid_modulus_size(self):
        """Should handle invalid modulus size during base64 decoding."""
        # Create JWKS with extremely short modulus (invalid for RSA)
        invalid_jwks = {
            "keys": [
                {"kty": "RSA", "kid": "short-key", "n": "QQ", "e": "AQAB"}  # Very short base64 (decodes to single byte)
            ]
        }

        with patch("httpx.Client") as mock_client_class:
            mock_client = Mock()
            mock_client.__enter__ = Mock(return_value=mock_client)
            mock_client.__exit__ = Mock(return_value=None)
            mock_client_class.return_value = mock_client

            mock_response = Mock()
            mock_response.raise_for_status.return_value = None
            mock_response.json.return_value = invalid_jwks
            mock_client.get.return_value = mock_response

            # Should throw due to key being too weak (much less than 2048 bits)
            with pytest.raises(ValueError, match="RSA key too weak"):
                self.client.get_signing_key("short-key")

    def test_should_handle_pem_serialization_failure(self):
        """Should handle PEM serialization failure."""
        # Mock the PEM serialization to fail
        with patch("httpx.Client") as mock_client_class:

            # Setup HTTP mock
            mock_client = Mock()
            mock_client.__enter__ = Mock(return_value=mock_client)
            mock_client.__exit__ = Mock(return_value=None)
            mock_client_class.return_value = mock_client

            mock_response = Mock()
            mock_response.raise_for_status.return_value = None
            mock_response.json.return_value = VALID_JWKS_RESPONSE_DICT
            mock_client.get.return_value = mock_response

            # Mock the public_bytes method to raise an exception
            mock_key = Mock()
            mock_key.public_bytes.side_effect = Exception("PEM serialization failed")

            with patch("cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicNumbers") as mock_rsa_numbers:
                mock_public_numbers = Mock()
                mock_public_numbers.public_key.return_value = mock_key
                mock_rsa_numbers.return_value = mock_public_numbers

                # Should throw during PEM conversion due to serialization failure
                with pytest.raises(ValueError, match="Failed to convert JWK to PEM"):
                    self.client.get_signing_key("test-key-id")


class TestJWKSClientPEMConversion:
    @pytest.fixture(autouse=True)
    def setup_client(self):
        """Setup client before each test."""
        config = JWKSClientConfig(jwks_uri="https://test.example.com/jwks", cache_max_size=10)
        self.client = JWKSClient(config)

    def test_should_produce_properly_formatted_pem(self):
        """Should produce properly formatted PEM."""
        with patch("httpx.Client") as mock_client_class:
            mock_client = Mock()
            mock_client.__enter__ = Mock(return_value=mock_client)
            mock_client.__exit__ = Mock(return_value=None)
            mock_client_class.return_value = mock_client

            mock_response = Mock()
            mock_response.raise_for_status.return_value = None
            mock_response.json.return_value = VALID_JWKS_RESPONSE_DICT
            mock_client.get.return_value = mock_response

            pem = self.client.get_signing_key("test-key-id")

            # Check PEM format
            assert pem.startswith("-----BEGIN PUBLIC KEY-----\n")
            assert pem.endswith("\n-----END PUBLIC KEY-----\n")

            # Check proper line structure
            lines = pem.strip().split("\n")
            assert lines[0] == "-----BEGIN PUBLIC KEY-----"
            assert lines[-1] == "-----END PUBLIC KEY-----"

            # Body lines should be <= 64 characters (standard PEM format)
            for i in range(1, len(lines) - 1):
                assert len(lines[i]) <= 64

    def test_should_handle_jwk_with_minimal_parameters(self):
        """Should handle JWK with minimal parameters."""
        # JWK with only required parameters (no 'use' or other optional fields)
        minimal_jwks = {
            "keys": [
                {
                    "kty": "RSA",
                    "kid": "minimal-key",
                    "n": create_2048_bit_modulus(),
                    "e": "AQAB",
                    # No 'use' or other optional parameters
                }
            ]
        }

        with patch("httpx.Client") as mock_client_class:
            mock_client = Mock()
            mock_client.__enter__ = Mock(return_value=mock_client)
            mock_client.__exit__ = Mock(return_value=None)
            mock_client_class.return_value = mock_client

            mock_response = Mock()
            mock_response.raise_for_status.return_value = None
            mock_response.json.return_value = minimal_jwks
            mock_client.get.return_value = mock_response

            pem = self.client.get_signing_key("minimal-key")
            assert re.match(r"^-----BEGIN PUBLIC KEY-----", pem)

    def test_should_handle_different_exponent_values(self):
        """Should handle JWK with different exponent values."""
        # JWK with different exponent (but still valid)
        # e=3 is a valid RSA exponent (base64url encoded as 'Aw')
        different_exp_jwks = {
            "keys": [
                {
                    "kty": "RSA",
                    "kid": "different-exp-key",
                    "n": create_2048_bit_modulus(),
                    "e": "Aw",  # e=3 (different from standard AQAB which is 65537)
                    "use": "sig",
                }
            ]
        }

        with patch("httpx.Client") as mock_client_class:
            mock_client = Mock()
            mock_client.__enter__ = Mock(return_value=mock_client)
            mock_client.__exit__ = Mock(return_value=None)
            mock_client_class.return_value = mock_client

            mock_response = Mock()
            mock_response.raise_for_status.return_value = None
            mock_response.json.return_value = different_exp_jwks
            mock_client.get.return_value = mock_response

            pem = self.client.get_signing_key("different-exp-key")
            assert re.match(r"^-----BEGIN PUBLIC KEY-----", pem)


class TestJWKSClientASN1EdgeCases:
    """Test ASN.1 encoding edge cases."""

    @pytest.fixture(autouse=True)
    def setup_client(self):
        """Setup client before each test."""
        config = JWKSClientConfig(jwks_uri="https://test.example.com/jwks", cache_max_size=10)
        self.client = JWKSClient(config)

    def test_should_handle_rsa_parameters_with_msb_set(self):
        """Should handle RSA parameters with MSB set (requiring padding)."""
        # Create 2048-bit modulus with MSB set (starts with 0x80+)
        # This tests ASN.1 INTEGER encoding edge case
        import base64

        # Create bytes with MSB set
        msb_bytes = bytearray(256)  # 2048 bits
        for i in range(len(msb_bytes)):
            msb_bytes[i] = 0x41
        msb_bytes[0] = 0x80  # Set MSB to trigger padding in ASN.1 encoding

        msb_modulus = base64.b64encode(msb_bytes).decode("ascii").replace("+", "-").replace("/", "_").replace("=", "")

        msb_set_jwks = {"keys": [{"kty": "RSA", "kid": "msb-set-key", "n": msb_modulus, "e": "AQAB"}]}

        with patch("httpx.Client") as mock_client_class:
            mock_client = Mock()
            mock_client.__enter__ = Mock(return_value=mock_client)
            mock_client.__exit__ = Mock(return_value=None)
            mock_client_class.return_value = mock_client

            mock_response = Mock()
            mock_response.raise_for_status.return_value = None
            mock_response.json.return_value = msb_set_jwks
            mock_client.get.return_value = mock_response

            pem = self.client.get_signing_key("msb-set-key")
            assert re.match(r"^-----BEGIN PUBLIC KEY-----", pem)
