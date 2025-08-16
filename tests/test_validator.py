import json
import time
from unittest.mock import Mock, patch

import pytest

from wristband.python_jwt.models import WristbandJwtValidatorConfig
from wristband.python_jwt.validator import WristbandJwtValidatorImpl, create_wristband_jwt_validator


class TestWristbandJwtValidatorImpl:
    def setup_method(self):
        """Set up test fixtures."""
        self.valid_issuer = "https://test.wristband.dev"
        self.mock_jwks_client = Mock()
        self.mock_jwks_client.get_signing_key.return_value = "mock-public-key"

        self.validator = WristbandJwtValidatorImpl(self.mock_jwks_client, self.valid_issuer)

        # Valid test data
        self.valid_header = {"alg": "RS256", "kid": "test-key-id"}
        self.valid_payload = {
            "iss": self.valid_issuer,
            "exp": int(time.time()) + 3600,  # 1 hour from now
            "sub": "user123",
        }

    def teardown_method(self):
        """Clean up after each test."""
        # Reset mocks
        self.mock_jwks_client.reset_mock()

    # Constructor Tests
    def test_constructor_with_valid_parameters(self):
        """Should create validator with valid parameters."""
        validator = WristbandJwtValidatorImpl(self.mock_jwks_client, self.valid_issuer)
        assert validator._jwks_client == self.mock_jwks_client
        assert validator._issuer == self.valid_issuer
        assert validator._algorithms == ["RS256"]

    def test_constructor_with_null_jwks_client(self):
        """Should throw error when jwksClient is None."""
        with pytest.raises(ValueError, match="JWKSClient must be provided to the validator"):
            WristbandJwtValidatorImpl(None, self.valid_issuer)

    def test_constructor_with_empty_issuer(self):
        """Should throw error when issuer is empty."""
        with pytest.raises(ValueError, match="A valid issuer must be provided to the validator"):
            WristbandJwtValidatorImpl(self.mock_jwks_client, "")

    def test_constructor_with_whitespace_issuer(self):
        """Should throw error when issuer is whitespace only."""
        with pytest.raises(ValueError, match="A valid issuer must be provided to the validator"):
            WristbandJwtValidatorImpl(self.mock_jwks_client, "   ")

    def test_constructor_accepts_rs256_algorithm(self):
        """Should accept RS256 algorithm."""
        validator = WristbandJwtValidatorImpl(self.mock_jwks_client, self.valid_issuer, ["RS256"])
        assert validator._algorithms == ["RS256"]

    def test_constructor_rejects_non_rs256_algorithm(self):
        """Should throw error for single non-RS256 algorithm."""
        with pytest.raises(ValueError, match="Only the RS256 algorithm is supported"):
            WristbandJwtValidatorImpl(self.mock_jwks_client, self.valid_issuer, ["HS256"])

    def test_constructor_rejects_multiple_algorithms(self):
        """Should throw error for multiple algorithms."""
        with pytest.raises(ValueError, match="Only the RS256 algorithm is supported"):
            WristbandJwtValidatorImpl(self.mock_jwks_client, self.valid_issuer, ["HS256", "ES256"])

    def test_constructor_rejects_empty_algorithms_array(self):
        """Should throw error for empty algorithms array."""
        with pytest.raises(ValueError, match="Only the RS256 algorithm is supported"):
            WristbandJwtValidatorImpl(self.mock_jwks_client, self.valid_issuer, [])

    # extract_bearer_token Tests
    def test_extract_bearer_token_from_valid_string(self):
        """Should extract token from valid Bearer header string."""
        result = self.validator.extract_bearer_token("Bearer abc123")
        assert result == "abc123"

    def test_extract_bearer_token_from_valid_array(self):
        """Should extract token from valid Bearer header array."""
        result = self.validator.extract_bearer_token(["Bearer abc123"])
        assert result == "abc123"

    def test_extract_bearer_token_with_complex_token(self):
        """Should handle Bearer header with complex token."""
        complex_token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature"
        result = self.validator.extract_bearer_token(f"Bearer {complex_token}")
        assert result == complex_token

    def test_extract_bearer_token_null_header(self):
        """Should throw error for null header."""
        with pytest.raises(ValueError, match="No authorization header provided"):
            self.validator.extract_bearer_token(None)

    def test_extract_bearer_token_empty_array(self):
        """Should throw error for empty array."""
        with pytest.raises(ValueError, match="No authorization header provided"):
            self.validator.extract_bearer_token([])

    def test_extract_bearer_token_empty_array_specific_condition(self):
        """Should throw error for empty array hitting the len() == 0 check specifically."""

        class TruthyEmptyList(list):
            """A list that evaluates to True even when empty."""

            def __bool__(self):
                return True

        empty_but_truthy = TruthyEmptyList()

        with pytest.raises(ValueError, match="No authorization header provided"):
            self.validator.extract_bearer_token(empty_but_truthy)

    def test_extract_bearer_token_multiple_headers(self):
        """Should throw error for multiple headers."""
        with pytest.raises(ValueError, match="Multiple authorization headers not allowed"):
            self.validator.extract_bearer_token(["Bearer abc", "Bearer xyz"])

    def test_extract_bearer_token_empty_string_in_array(self):
        """Should throw error for empty string in array."""
        with pytest.raises(ValueError, match="No authorization header provided"):
            self.validator.extract_bearer_token([""])

    def test_extract_bearer_token_whitespace_string_in_array(self):
        """Should throw error for whitespace-only string in array."""
        with pytest.raises(ValueError, match="No authorization header provided"):
            self.validator.extract_bearer_token(["   "])

    def test_extract_bearer_token_basic_auth_scheme(self):
        """Should throw error for Basic auth scheme."""
        with pytest.raises(ValueError, match='Authorization header must provide "Bearer" token'):
            self.validator.extract_bearer_token("Basic abc123")

    def test_extract_bearer_token_no_auth_scheme(self):
        """Should throw error for no auth scheme."""
        with pytest.raises(ValueError, match='Authorization header must provide "Bearer" token'):
            self.validator.extract_bearer_token("abc123")

    def test_extract_bearer_token_case_sensitive_bearer(self):
        """Should throw error for case-sensitive Bearer."""
        with pytest.raises(ValueError, match='Authorization header must provide "Bearer" token'):
            self.validator.extract_bearer_token("bearer abc123")

    def test_extract_bearer_token_bearer_without_token(self):
        """Should throw error for Bearer without token."""
        with pytest.raises(ValueError, match="No token provided"):
            self.validator.extract_bearer_token("Bearer ")

    def test_extract_bearer_token_bearer_only(self):
        """Should throw error for Bearer only."""
        with pytest.raises(ValueError, match='Authorization header must provide "Bearer" token'):
            self.validator.extract_bearer_token("Bearer")

    # validate() Tests
    def test_validate_null_token(self):
        """Should return invalid for null token."""
        result = self.validator.validate(None)
        assert result.is_valid is False
        assert result.error_message == "No token provided"

    def test_validate_empty_token(self):
        """Should return invalid for empty token."""
        result = self.validator.validate("")
        assert result.is_valid is False
        assert result.error_message == "No token provided"

    def test_validate_malformed_jwt_wrong_parts(self):
        """Should return invalid for malformed JWT (wrong number of parts)."""
        result = self.validator.validate("invalid.jwt")
        assert result.is_valid is False
        assert result.error_message == "Invalid JWT format"

    def test_validate_jwt_too_many_parts(self):
        """Should return invalid for JWT with too many parts."""
        result = self.validator.validate("part1.part2.part3.part4")
        assert result.is_valid is False
        assert result.error_message == "Invalid JWT format"

    @patch("wristband.python_jwt.validator.base64url_decode")
    def test_validate_invalid_base64_encoding(self, mock_decode):
        """Should return invalid for JWT with invalid base64 encoding."""
        mock_decode.side_effect = Exception("Invalid base64")

        result = self.validator.validate("header.payload.signature")
        assert result.is_valid is False
        assert result.error_message == "Invalid JWT encoding"

    @patch("wristband.python_jwt.validator.base64url_decode")
    def test_validate_invalid_json_in_header(self, mock_decode):
        """Should return invalid for JWT with invalid JSON in header."""
        mock_decode.side_effect = ["invalid-json", json.dumps(self.valid_payload)]

        result = self.validator.validate("header.payload.signature")
        assert result.is_valid is False
        assert result.error_message == "Invalid JWT encoding"

    @patch("wristband.python_jwt.validator.base64url_decode")
    @patch("wristband.python_jwt.validator.validate_algorithm")
    def test_validate_unsupported_algorithm(self, mock_validate_alg, mock_decode):
        """Should return invalid for unsupported algorithm."""
        header_with_bad_alg = {**self.valid_header, "alg": "HS256"}
        mock_decode.side_effect = [json.dumps(header_with_bad_alg), json.dumps(self.valid_payload)]
        mock_validate_alg.return_value = False

        result = self.validator.validate("header.payload.signature")
        assert result.is_valid is False
        assert result.error_message == "Algorithm HS256 not allowed. Expected one of: RS256"

    @patch("wristband.python_jwt.validator.base64url_decode")
    @patch("wristband.python_jwt.validator.validate_algorithm")
    def test_validate_accepts_rs256_algorithm(self, mock_validate_alg, mock_decode):
        """Should accept RS256 algorithm during validation."""
        mock_decode.side_effect = [json.dumps(self.valid_header), json.dumps(self.valid_payload)]
        mock_validate_alg.return_value = True

        with patch("wristband.python_jwt.validator.verify_rs256_signature", return_value=True):
            result = self.validator.validate("header.payload.signature")
            assert result.is_valid is True
            mock_validate_alg.assert_called_with("RS256", ["RS256"])

    @patch("wristband.python_jwt.validator.base64url_decode")
    def test_validate_wrong_issuer(self, mock_decode):
        """Should return invalid for wrong issuer."""
        payload_with_bad_issuer = {**self.valid_payload, "iss": "https://wrong-issuer.com"}
        mock_decode.side_effect = [json.dumps(self.valid_header), json.dumps(payload_with_bad_issuer)]

        result = self.validator.validate("header.payload.signature")
        assert result.is_valid is False
        assert result.error_message == f"Invalid issuer. Expected {self.valid_issuer}, got https://wrong-issuer.com"

    @patch("wristband.python_jwt.validator.base64url_decode")
    def test_validate_expired_token(self, mock_decode):
        """Should return invalid for expired token."""
        expired_payload = {**self.valid_payload, "exp": int(time.time()) - 3600}  # 1 hour ago
        mock_decode.side_effect = [json.dumps(self.valid_header), json.dumps(expired_payload)]

        result = self.validator.validate("header.payload.signature")
        assert result.is_valid is False
        assert result.error_message == "Token has expired"

    @patch("wristband.python_jwt.validator.base64url_decode")
    def test_validate_token_not_yet_valid(self, mock_decode):
        """Should return invalid for token not yet valid (nbf)."""
        future_payload = {**self.valid_payload, "nbf": int(time.time()) + 3600}  # 1 hour from now
        mock_decode.side_effect = [json.dumps(self.valid_header), json.dumps(future_payload)]

        result = self.validator.validate("header.payload.signature")
        assert result.is_valid is False
        assert result.error_message == "Token not yet valid"

    @patch("wristband.python_jwt.validator.base64url_decode")
    @patch("wristband.python_jwt.validator.validate_algorithm")
    @patch("wristband.python_jwt.validator.verify_rs256_signature")
    def test_validate_token_without_exp_claim(self, mock_verify, mock_validate_alg, mock_decode):
        """Should pass validation for token without exp claim."""
        payload_without_exp = {k: v for k, v in self.valid_payload.items() if k != "exp"}
        mock_decode.side_effect = [json.dumps(self.valid_header), json.dumps(payload_without_exp)]
        mock_validate_alg.return_value = True
        mock_verify.return_value = True

        result = self.validator.validate("header.payload.signature")
        assert result.is_valid is True

    @patch("wristband.python_jwt.validator.base64url_decode")
    def test_validate_missing_kid_in_header(self, mock_decode):
        """Should return invalid for missing kid in header."""
        # Create header with empty/None kid to reach the validation logic
        header_with_empty_kid = {**self.valid_header, "kid": None}
        mock_decode.side_effect = [json.dumps(header_with_empty_kid), json.dumps(self.valid_payload)]

        result = self.validator.validate("header.payload.signature")
        assert result.is_valid is False
        assert result.error_message == "Token header missing kid (key ID)"

    @patch("wristband.python_jwt.validator.base64url_decode")
    @patch("wristband.python_jwt.validator.validate_algorithm")
    def test_validate_jwks_client_error(self, mock_validate_alg, mock_decode):
        """Should return invalid when JWKS client throws error."""
        mock_decode.side_effect = [json.dumps(self.valid_header), json.dumps(self.valid_payload)]
        mock_validate_alg.return_value = True
        self.mock_jwks_client.get_signing_key.side_effect = Exception("JWKS fetch failed")

        result = self.validator.validate("header.payload.signature")
        assert result.is_valid is False
        assert result.error_message == "Failed to get signing key: JWKS fetch failed"

    @patch("wristband.python_jwt.validator.base64url_decode")
    @patch("wristband.python_jwt.validator.validate_algorithm")
    @patch("wristband.python_jwt.validator.verify_rs256_signature")
    def test_validate_invalid_signature(self, mock_verify, mock_validate_alg, mock_decode):
        """Should return invalid for invalid signature."""
        mock_decode.side_effect = [json.dumps(self.valid_header), json.dumps(self.valid_payload)]
        mock_validate_alg.return_value = True
        mock_verify.return_value = False

        result = self.validator.validate("header.payload.signature")
        assert result.is_valid is False
        assert result.error_message == "Invalid signature"

    @patch("wristband.python_jwt.validator.base64url_decode")
    @patch("wristband.python_jwt.validator.validate_algorithm")
    @patch("wristband.python_jwt.validator.verify_rs256_signature")
    def test_validate_successful_validation(self, mock_verify, mock_validate_alg, mock_decode):
        """Should return valid result for completely valid token."""
        mock_decode.side_effect = [json.dumps(self.valid_header), json.dumps(self.valid_payload)]
        mock_validate_alg.return_value = True
        mock_verify.return_value = True

        result = self.validator.validate("header.payload.signature")
        assert result.is_valid is True
        # Check that payload was created correctly
        assert result.payload is not None
        assert result.payload.iss == self.valid_issuer
        assert result.payload.sub == "user123"

    @patch("wristband.python_jwt.validator.base64url_decode")
    @patch("wristband.python_jwt.validator.validate_algorithm")
    @patch("wristband.python_jwt.validator.verify_rs256_signature")
    def test_validate_calls_crypto_functions_correctly(self, mock_verify, mock_validate_alg, mock_decode):
        """Should call crypto functions with correct parameters."""
        mock_decode.side_effect = [json.dumps(self.valid_header), json.dumps(self.valid_payload)]
        mock_validate_alg.return_value = True
        mock_verify.return_value = True

        result = self.validator.validate("header.payload.signature")

        # Verify the result is successful
        assert result.is_valid is True

        # Check that functions were called with correct parameters
        mock_validate_alg.assert_called_with("RS256", ["RS256"])
        self.mock_jwks_client.get_signing_key.assert_called_with("test-key-id")
        mock_verify.assert_called_with("header.payload", "signature", "mock-public-key")


class TestCreateWristbandJwtValidator:
    """Test create_wristband_jwt_validator factory function."""

    @patch("wristband.python_jwt.validator.create_jwks_client")
    def test_create_validator_with_correct_configuration(self, mock_create_jwks_client):
        """Should create validator with correct configuration."""
        mock_jwks_client = Mock()
        mock_create_jwks_client.return_value = mock_jwks_client

        config = WristbandJwtValidatorConfig(
            wristband_application_vanity_domain="test.wristband.dev", jwks_cache_max_size=15, jwks_cache_ttl=3600000
        )

        validator = create_wristband_jwt_validator(config)

        assert isinstance(validator, WristbandJwtValidatorImpl)

        # Check that create_jwks_client was called once
        mock_create_jwks_client.assert_called_once()

        # Get the actual config object that was passed
        call_args = mock_create_jwks_client.call_args[0][0]

        # Check the config values
        assert call_args.jwks_uri == "https://test.wristband.dev/api/v1/oauth2/jwks"
        assert call_args.cache_max_size == 15
        assert call_args.cache_ttl == 3600000

    @patch("wristband.python_jwt.validator.create_jwks_client")
    def test_create_validator_with_default_cache_size(self, mock_create_jwks_client):
        """Should use default cache size when not provided."""
        mock_jwks_client = Mock()
        mock_create_jwks_client.return_value = mock_jwks_client

        config = WristbandJwtValidatorConfig(wristband_application_vanity_domain="test.wristband.dev")

        validator = create_wristband_jwt_validator(config)

        assert isinstance(validator, WristbandJwtValidatorImpl)

        # Check that create_jwks_client was called once
        mock_create_jwks_client.assert_called_once()

        # Get the actual config object that was passed
        call_args = mock_create_jwks_client.call_args[0][0]

        # Check the config values
        assert call_args.jwks_uri == "https://test.wristband.dev/api/v1/oauth2/jwks"
        assert call_args.cache_max_size == 20  # default value
        assert call_args.cache_ttl is None

    @patch("wristband.python_jwt.validator.create_jwks_client")
    def test_create_validator_constructs_proper_issuer_url(self, mock_create_jwks_client):
        """Should construct proper issuer URL."""
        mock_jwks_client = Mock()
        mock_create_jwks_client.return_value = mock_jwks_client

        config = WristbandJwtValidatorConfig(
            wristband_application_vanity_domain="myapp.wristband.dev", jwks_cache_max_size=10
        )

        validator = create_wristband_jwt_validator(config)

        assert isinstance(validator, WristbandJwtValidatorImpl)

        # Check that create_jwks_client was called once
        mock_create_jwks_client.assert_called_once()

        # Get the actual config object that was passed
        call_args = mock_create_jwks_client.call_args[0][0]

        # Check the config values
        assert call_args.jwks_uri == "https://myapp.wristband.dev/api/v1/oauth2/jwks"
        assert call_args.cache_max_size == 10
        assert call_args.cache_ttl is None

    @patch("wristband.python_jwt.validator.create_jwks_client")
    def test_create_validator_undefined_cache_ttl(self, mock_create_jwks_client):
        """Should pass None cacheTtl when not provided."""
        mock_jwks_client = Mock()
        mock_create_jwks_client.return_value = mock_jwks_client

        config = WristbandJwtValidatorConfig(
            wristband_application_vanity_domain="test.wristband.dev", jwks_cache_max_size=5
        )

        validator = create_wristband_jwt_validator(config)

        assert isinstance(validator, WristbandJwtValidatorImpl)

        # Check that create_jwks_client was called once
        mock_create_jwks_client.assert_called_once()

        # Get the actual config object that was passed
        call_args = mock_create_jwks_client.call_args[0][0]

        # Check the config values
        assert call_args.jwks_uri == "https://test.wristband.dev/api/v1/oauth2/jwks"
        assert call_args.cache_max_size == 5
        assert call_args.cache_ttl is None  # should be None when not set (cached indefinitely)
