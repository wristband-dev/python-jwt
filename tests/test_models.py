import pytest

from wristband.python_jwt.models import (
    CacheOptions,
    JWKSClientConfig,
    JWKSKey,
    JWKSResponse,
    JWTHeader,
    JWTPayload,
    JwtValidationResult,
    LRUNode,
    WristbandJwtValidatorConfig,
)


class TestWristbandJwtValidatorConfig:
    def test_initialization_required_params(self):
        """Should initialize with required parameters."""
        config = WristbandJwtValidatorConfig("app.wristband.dev")

        assert config.wristband_application_vanity_domain == "app.wristband.dev"
        assert config.jwks_cache_max_size is None
        assert config.jwks_cache_ttl is None

    def test_initialization_all_params(self):
        """Should initialize with all parameters."""
        config = WristbandJwtValidatorConfig(
            wristband_application_vanity_domain="app.wristband.dev", jwks_cache_max_size=50, jwks_cache_ttl=3600000
        )

        assert config.wristband_application_vanity_domain == "app.wristband.dev"
        assert config.jwks_cache_max_size == 50
        assert config.jwks_cache_ttl == 3600000

    def test_initialization_partial_params(self):
        """Should initialize with partial optional parameters."""
        config = WristbandJwtValidatorConfig(
            wristband_application_vanity_domain="app.wristband.dev", jwks_cache_max_size=100
        )

        assert config.wristband_application_vanity_domain == "app.wristband.dev"
        assert config.jwks_cache_max_size == 100
        assert config.jwks_cache_ttl is None

    def test_domain_validation(self):
        """Should handle various domain formats."""
        valid_domains = ["app.wristband.dev", "subdomain.app.wristband.dev", "localhost:8080", "192.168.1.1:3000"]

        for domain in valid_domains:
            config = WristbandJwtValidatorConfig(domain)
            assert config.wristband_application_vanity_domain == domain


class TestJWTPayload:
    @pytest.fixture
    def sample_payload_dict(self):
        """Sample JWT payload for testing."""
        return {
            "iss": "https://app.wristband.dev",
            "sub": "user123",
            "aud": ["api1", "api2"],
            "exp": 1640995200,
            "nbf": 1640908800,
            "iat": 1640908800,
            "jti": "jwt123",
            "custom_claim": "custom_value",
            "role": "admin",
        }

    @pytest.fixture
    def jwt_payload(self, sample_payload_dict):
        """JWTPayload instance for testing."""
        return JWTPayload(sample_payload_dict)

    def test_initialization(self, sample_payload_dict):
        """Should initialize with payload dictionary."""
        payload = JWTPayload(sample_payload_dict)
        assert payload._payload == sample_payload_dict

    def test_iss_property(self, jwt_payload):
        """Should return issuer claim."""
        assert jwt_payload.iss == "https://app.wristband.dev"

    def test_sub_property(self, jwt_payload):
        """Should return subject claim."""
        assert jwt_payload.sub == "user123"

    def test_aud_property(self, jwt_payload):
        """Should return audience claim."""
        assert jwt_payload.aud == ["api1", "api2"]

    def test_exp_property(self, jwt_payload):
        """Should return expiration claim."""
        assert jwt_payload.exp == 1640995200

    def test_nbf_property(self, jwt_payload):
        """Should return not-before claim."""
        assert jwt_payload.nbf == 1640908800

    def test_iat_property(self, jwt_payload):
        """Should return issued-at claim."""
        assert jwt_payload.iat == 1640908800

    def test_jti_property(self, jwt_payload):
        """Should return JWT ID claim."""
        assert jwt_payload.jti == "jwt123"

    def test_missing_standard_claims(self):
        """Should return None for missing standard claims."""
        payload = JWTPayload({"custom": "value"})

        assert payload.iss is None
        assert payload.sub is None
        assert payload.aud is None
        assert payload.exp is None
        assert payload.nbf is None
        assert payload.iat is None
        assert payload.jti is None

    def test_get_method(self, jwt_payload):
        """Should get claims using get method."""
        assert jwt_payload.get("custom_claim") == "custom_value"
        assert jwt_payload.get("missing_claim") is None
        assert jwt_payload.get("missing_claim", "default") == "default"

    def test_getitem_method(self, jwt_payload):
        """Should support dict-like access."""
        assert jwt_payload["custom_claim"] == "custom_value"
        assert jwt_payload["role"] == "admin"

    def test_getitem_keyerror(self, jwt_payload):
        """Should raise KeyError for missing keys."""
        with pytest.raises(KeyError):
            jwt_payload["missing_key"]

    def test_contains_method(self, jwt_payload):
        """Should support 'in' operator."""
        assert "custom_claim" in jwt_payload
        assert "role" in jwt_payload
        assert "missing_claim" not in jwt_payload

    def test_to_dict_method(self, jwt_payload, sample_payload_dict):
        """Should return copy of payload dictionary."""
        result = jwt_payload.to_dict()

        assert result == sample_payload_dict
        assert result is not jwt_payload._payload  # Should be a copy

    def test_aud_single_string(self):
        """Should handle audience as single string."""
        payload = JWTPayload({"aud": "single-audience"})
        assert payload.aud == "single-audience"

    def test_empty_payload(self):
        """Should handle empty payload."""
        payload = JWTPayload({})

        assert payload.iss is None
        assert payload.sub is None
        assert payload.aud is None
        assert payload.get("anything") is None
        assert "anything" not in payload
        assert payload.to_dict() == {}


class TestJwtValidationResult:
    """Test JwtValidationResult class."""

    def test_initialization_valid_result(self):
        """Should initialize valid result."""
        payload = JWTPayload({"sub": "user123"})
        result = JwtValidationResult(is_valid=True, payload=payload, error_message=None)

        assert result.is_valid is True
        assert result.payload == payload
        assert result.error_message is None

    def test_initialization_invalid_result(self):
        """Should initialize invalid result."""
        result = JwtValidationResult(is_valid=False, payload=None, error_message="Token expired")

        assert result.is_valid is False
        assert result.payload is None
        assert result.error_message == "Token expired"

    def test_initialization_minimal(self):
        """Should initialize with minimal parameters."""
        result = JwtValidationResult(is_valid=True)

        assert result.is_valid is True
        assert result.payload is None
        assert result.error_message is None

    def test_initialization_defaults(self):
        """Should use default values for optional parameters."""
        result = JwtValidationResult(False)

        assert result.is_valid is False
        assert result.payload is None
        assert result.error_message is None


class TestJWKSClientConfig:
    """Test JWKSClientConfig class."""

    def test_initialization_required_params(self):
        """Should initialize with required parameters."""
        config = JWKSClientConfig("https://app.wristband.dev/.well-known/jwks.json")

        assert config.jwks_uri == "https://app.wristband.dev/.well-known/jwks.json"
        assert config.cache_max_size is None
        assert config.cache_ttl is None

    def test_initialization_all_params(self):
        """Should initialize with all parameters."""
        config = JWKSClientConfig(
            jwks_uri="https://app.wristband.dev/.well-known/jwks.json", cache_max_size=100, cache_ttl=7200000
        )

        assert config.jwks_uri == "https://app.wristband.dev/.well-known/jwks.json"
        assert config.cache_max_size == 100
        assert config.cache_ttl == 7200000

    def test_various_uri_formats(self):
        """Should handle various URI formats."""
        uris = [
            "https://app.wristband.dev/.well-known/jwks.json",
            "http://localhost:8080/jwks",
            "https://api.example.com/auth/jwks",
            "https://subdomain.app.wristband.dev/keys",
        ]

        for uri in uris:
            config = JWKSClientConfig(uri)
            assert config.jwks_uri == uri


class TestJWKSKey:
    """Test JWKSKey class."""

    @pytest.fixture
    def sample_jwk_dict(self):
        """Sample JWK dictionary for testing."""
        return {
            "kty": "RSA",
            "kid": "key123",
            "use": "sig",
            "n": (
                "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tS"
                "oc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65"
                "YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyr"
                "dkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzK"
                "nqDK"
                "gw"
            ),
            "e": "AQAB",
            "alg": "RS256",
        }

    @pytest.fixture
    def jwks_key(self, sample_jwk_dict):
        """JWKSKey instance for testing."""
        return JWKSKey(sample_jwk_dict)

    def test_initialization(self, sample_jwk_dict):
        """Should initialize with key dictionary."""
        key = JWKSKey(sample_jwk_dict)
        assert key._key == sample_jwk_dict

    def test_kty_property(self, jwks_key):
        """Should return key type."""
        assert jwks_key.kty == "RSA"

    def test_kid_property(self, jwks_key):
        """Should return key ID."""
        assert jwks_key.kid == "key123"

    def test_use_property(self, jwks_key):
        """Should return key use."""
        assert jwks_key.use == "sig"

    def test_n_property(self, jwks_key):
        """Should return RSA modulus."""
        expected_n = (
            "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc"
            "_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQ"
            "R0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bF"
            "TWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"
        )
        assert jwks_key.n == expected_n

    def test_e_property(self, jwks_key):
        """Should return RSA exponent."""
        assert jwks_key.e == "AQAB"

    def test_alg_property(self, jwks_key):
        """Should return algorithm."""
        assert jwks_key.alg == "RS256"

    def test_missing_properties(self):
        """Should handle missing properties (will raise KeyError as per cast)."""
        incomplete_key = JWKSKey({"kty": "RSA"})

        # These should raise KeyError due to cast() expecting the keys to exist
        with pytest.raises(KeyError):
            incomplete_key.kid

        with pytest.raises(KeyError):
            incomplete_key.use

        with pytest.raises(KeyError):
            incomplete_key.n


class TestJWKSResponse:
    """Test JWKSResponse class."""

    @pytest.fixture
    def sample_jwks_dict(self):
        """Sample JWKS response dictionary."""
        return {
            "keys": [
                {"kty": "RSA", "kid": "key1", "use": "sig", "n": "modulus1", "e": "AQAB", "alg": "RS256"},
                {"kty": "RSA", "kid": "key2", "use": "sig", "n": "modulus2", "e": "AQAB", "alg": "RS256"},
            ]
        }

    def test_initialization(self, sample_jwks_dict):
        """Should initialize with response dictionary."""
        response = JWKSResponse(sample_jwks_dict)

        assert len(response.keys) == 2
        assert all(isinstance(key, JWKSKey) for key in response.keys)
        assert response.keys[0].kid == "key1"
        assert response.keys[1].kid == "key2"

    def test_empty_keys(self):
        """Should handle empty keys array."""
        response = JWKSResponse({"keys": []})
        assert len(response.keys) == 0
        assert response.keys == []

    def test_missing_keys(self):
        """Should handle missing keys field."""
        response = JWKSResponse({})
        assert len(response.keys) == 0
        assert response.keys == []

    def test_single_key(self):
        """Should handle single key in response."""
        response_dict = {
            "keys": [{"kty": "RSA", "kid": "only_key", "use": "sig", "n": "modulus", "e": "AQAB", "alg": "RS256"}]
        }

        response = JWKSResponse(response_dict)
        assert len(response.keys) == 1
        assert response.keys[0].kid == "only_key"


class TestJWTHeader:
    """Test JWTHeader class."""

    @pytest.fixture
    def sample_header_dict(self):
        """Sample JWT header dictionary."""
        return {"alg": "RS256", "typ": "JWT", "kid": "key123"}

    @pytest.fixture
    def jwt_header(self, sample_header_dict):
        """JWTHeader instance for testing."""
        return JWTHeader(sample_header_dict)

    def test_initialization(self, sample_header_dict):
        """Should initialize with header dictionary."""
        header = JWTHeader(sample_header_dict)
        assert header._header == sample_header_dict

    def test_alg_property(self, jwt_header):
        """Should return algorithm."""
        assert jwt_header.alg == "RS256"

    def test_typ_property(self, jwt_header):
        """Should return type."""
        assert jwt_header.typ == "JWT"

    def test_kid_property(self, jwt_header):
        """Should return key ID."""
        assert jwt_header.kid == "key123"

    def test_missing_properties(self):
        """Should handle missing properties (will raise KeyError due to cast)."""
        incomplete_header = JWTHeader({"alg": "RS256"})

        assert incomplete_header.alg == "RS256"

        # These should raise KeyError due to cast() expecting the keys to exist
        with pytest.raises(KeyError):
            incomplete_header.typ

        with pytest.raises(KeyError):
            incomplete_header.kid

    def test_various_algorithms(self):
        """Should handle various algorithm values."""
        algorithms = ["RS256", "RS384", "RS512", "HS256"]

        for alg in algorithms:
            header = JWTHeader({"alg": alg, "typ": "JWT", "kid": "key1"})
            assert header.alg == alg


class TestCacheOptions:
    """Test CacheOptions class."""

    def test_initialization_valid_params(self):
        """Should initialize with valid parameters."""
        options = CacheOptions(max_size=100, ttl=3600000)

        assert options.max_size == 100
        assert options.ttl == 3600000

    def test_initialization_no_ttl(self):
        """Should initialize without TTL."""
        options = CacheOptions(max_size=50)

        assert options.max_size == 50
        assert options.ttl is None

    def test_initialization_ttl_none(self):
        """Should initialize with explicit None TTL."""
        options = CacheOptions(max_size=75, ttl=None)

        assert options.max_size == 75
        assert options.ttl is None

    def test_max_size_validation_zero(self):
        """Should raise ValueError for zero max_size."""
        with pytest.raises(ValueError, match="max_size must be a positive integer"):
            CacheOptions(max_size=0)

    def test_max_size_validation_negative(self):
        """Should raise ValueError for negative max_size."""
        with pytest.raises(ValueError, match="max_size must be a positive integer"):
            CacheOptions(max_size=-1)

    def test_max_size_validation_float(self):
        """Should raise ValueError for float max_size."""
        with pytest.raises(ValueError, match="max_size must be a positive integer"):
            CacheOptions(max_size=10.5)

    def test_max_size_validation_string(self):
        """Should raise ValueError for string max_size."""
        with pytest.raises(ValueError, match="max_size must be a positive integer"):
            CacheOptions(max_size="10")

    def test_ttl_validation_zero(self):
        """Should raise ValueError for zero TTL."""
        with pytest.raises(ValueError, match="ttl must be a positive integer \\(if specified\\)"):
            CacheOptions(max_size=10, ttl=0)

    def test_ttl_validation_negative(self):
        """Should raise ValueError for negative TTL."""
        with pytest.raises(ValueError, match="ttl must be a positive integer \\(if specified\\)"):
            CacheOptions(max_size=10, ttl=-1000)

    def test_ttl_validation_float(self):
        """Should raise ValueError for float TTL."""
        with pytest.raises(ValueError, match="ttl must be a positive integer \\(if specified\\)"):
            CacheOptions(max_size=10, ttl=100.5)

    def test_ttl_validation_string(self):
        """Should raise ValueError for string TTL."""
        with pytest.raises(ValueError, match="ttl must be a positive integer \\(if specified\\)"):
            CacheOptions(max_size=10, ttl="100")

    def test_edge_case_max_size_one(self):
        """Should accept max_size of 1."""
        options = CacheOptions(max_size=1)
        assert options.max_size == 1

    def test_edge_case_large_values(self):
        """Should accept large values."""
        options = CacheOptions(max_size=1000000, ttl=86400000)  # 1 day in ms
        assert options.max_size == 1000000
        assert options.ttl == 86400000


class TestLRUNode:
    """Test LRUNode class."""

    def test_initialization_defaults(self):
        """Should initialize with default values."""
        node = LRUNode()

        assert node.key == ""
        assert node.value == ""
        assert node.last_accessed == 0
        assert node.prev is None
        assert node.next is None

    def test_initialization_with_params(self):
        """Should initialize with provided parameters."""
        timestamp = 1640908800000
        node = LRUNode(key="test_key", value="test_value", last_accessed=timestamp)

        assert node.key == "test_key"
        assert node.value == "test_value"
        assert node.last_accessed == timestamp
        assert node.prev is None
        assert node.next is None

    def test_initialization_with_links(self):
        """Should initialize with linked nodes."""
        prev_node = LRUNode(key="prev")
        next_node = LRUNode(key="next")

        node = LRUNode(
            key="current", value="current_value", last_accessed=1640908800000, prev=prev_node, next=next_node
        )

        assert node.key == "current"
        assert node.value == "current_value"
        assert node.prev == prev_node
        assert node.next == next_node

    def test_node_linking(self):
        """Should support manual node linking."""
        node1 = LRUNode(key="first", value="value1")
        node2 = LRUNode(key="second", value="value2")
        node3 = LRUNode(key="third", value="value3")

        # Link nodes manually
        node1.next = node2
        node2.prev = node1
        node2.next = node3
        node3.prev = node2

        # Verify links
        assert node1.next == node2
        assert node2.prev == node1
        assert node2.next == node3
        assert node3.prev == node2
        assert node1.prev is None
        assert node3.next is None

    def test_empty_strings(self):
        """Should handle empty string values."""
        node = LRUNode(key="", value="")

        assert node.key == ""
        assert node.value == ""

    def test_large_values(self):
        """Should handle large string values."""
        large_key = "k" * 1000
        large_value = "v" * 10000

        node = LRUNode(key=large_key, value=large_value)

        assert node.key == large_key
        assert node.value == large_value

    def test_special_characters(self):
        """Should handle special characters in key/value."""
        special_key = "key-with_special.chars@123"
        special_value = "value with spaces\nand\ttabs"

        node = LRUNode(key=special_key, value=special_value)

        assert node.key == special_key
        assert node.value == special_value

    def test_timestamp_values(self):
        """Should handle various timestamp values."""
        timestamps = [0, 1, 1640908800000, 9999999999999]

        for ts in timestamps:
            node = LRUNode(last_accessed=ts)
            assert node.last_accessed == ts


class TestModelIntegration:
    """Test integration between different model classes."""

    def test_jwt_validation_workflow(self):
        """Should support complete JWT validation workflow."""
        # Create configuration
        config = WristbandJwtValidatorConfig(
            wristband_application_vanity_domain="app.wristband.dev", jwks_cache_max_size=20, jwks_cache_ttl=3600000
        )

        # Create JWKS client config with same values as validator config
        jwks_config = JWKSClientConfig(
            jwks_uri=f"https://{config.wristband_application_vanity_domain}/.well-known/jwks.json",
            cache_max_size=config.jwks_cache_max_size,
            cache_ttl=config.jwks_cache_ttl,
        )

        # Create JWT header
        header = JWTHeader({"alg": "RS256", "typ": "JWT", "kid": "key123"})

        # Create JWT payload
        payload = JWTPayload(
            {
                "iss": f"https://{config.wristband_application_vanity_domain}",
                "sub": "user123",
                "aud": "api",
                "exp": 1640995200,
                "iat": 1640908800,
            }
        )

        # Create validation result
        result = JwtValidationResult(is_valid=True, payload=payload, error_message=None)

        # Verify integration between all components
        assert header.alg == "RS256"
        assert payload.iss == f"https://{config.wristband_application_vanity_domain}"
        assert result.is_valid is True
        assert result.payload == payload
        assert jwks_config.cache_max_size == config.jwks_cache_max_size
        assert jwks_config.cache_ttl == config.jwks_cache_ttl

    def test_jwks_workflow(self):
        """Should support JWKS fetching and parsing workflow."""
        # Create JWKS response
        jwks_data = {
            "keys": [{"kty": "RSA", "kid": "key1", "use": "sig", "n": "modulus1", "e": "AQAB", "alg": "RS256"}]
        }

        response = JWKSResponse(jwks_data)
        key = response.keys[0]

        # Verify key can be used for header matching
        header = JWTHeader({"alg": "RS256", "typ": "JWT", "kid": "key1"})

        assert header.kid == key.kid
        assert header.alg == key.alg
        assert key.kty == "RSA"
        assert key.use == "sig"

    def test_cache_options_integration(self):
        """Should integrate cache options with other configurations."""
        # Create cache options
        cache_opts = CacheOptions(max_size=50, ttl=1800000)

        # Use in validator configuration
        validator_config = WristbandJwtValidatorConfig(
            wristband_application_vanity_domain="app.wristband.dev",
            jwks_cache_max_size=cache_opts.max_size,
            jwks_cache_ttl=cache_opts.ttl,
        )

        # Use in JWKS client configuration
        jwks_config = JWKSClientConfig(
            jwks_uri="https://app.wristband.dev/.well-known/jwks.json",
            cache_max_size=cache_opts.max_size,
            cache_ttl=cache_opts.ttl,
        )

        # Verify all configurations use the same cache options
        assert validator_config.jwks_cache_max_size == jwks_config.cache_max_size == cache_opts.max_size
        assert validator_config.jwks_cache_ttl == jwks_config.cache_ttl == cache_opts.ttl

    def test_lru_node_cache_simulation(self):
        """Should simulate LRU cache node operations."""
        # Create dummy head and tail nodes
        head = LRUNode()  # Dummy head
        tail = LRUNode()  # Dummy tail
        head.next = tail
        tail.prev = head

        # Create actual cache node
        cache_node = LRUNode(key="jwk_key", value="jwk_pem_data", last_accessed=1640908800000)

        # Simulate adding node to cache (insert after head)
        cache_node.next = head.next
        cache_node.prev = head
        head.next.prev = cache_node
        head.next = cache_node

        # Verify the cache structure is correct
        assert head.next == cache_node
        assert cache_node.prev == head
        assert cache_node.next == tail
        assert tail.prev == cache_node
        assert cache_node.key == "jwk_key"
        assert cache_node.value == "jwk_pem_data"
