# Wristband Framework-Agnostic JWT Validation SDK for Python

Wristband provides enterprise-ready auth that is secure by default, truly multi-tenant, and ungated for small businesses.

- Website: [Wristband Website](https://wristband.dev)
- Documentation: [Wristband Docs](https://docs.wristband.dev/)

For detailed setup instructions and usage guidelines, visit the project's GitHub repository.

- [Python JWT SDK - GitHub](https://github.com/wristband-dev/python-jwt)


## Details

This SDK provides secure JWT validation capabilities for applications using Wristband authentication. It is framework-agnostic and works with FastAPI, Flask, Django, and other Python web frameworks. The SDK follows OWASP security best practices and is supported for Python 3.9+. Key functionalities include:

- Extracting Bearer tokens from HTTP Authorization headers.
- Validating JWT signatures using Wristband's JWKS endpoint.
- Verifying token claims including issuer, expiration, and algorithm allowlisting to prevent common JWT vulnerabilities.
- Automatic JWKS key caching and rotation for optimal performance.
- Comprehensive error handling with detailed validation messages.

You can learn more about JWTs in Wristband in our documentation:

- [JWTs and Signing Keys](https://docs.wristband.dev/docs/json-web-tokens-jwts-and-signing-keys)

## Questions

Reach out to the Wristband team at <support@wristband.dev> for any questions regarding this SDK.
