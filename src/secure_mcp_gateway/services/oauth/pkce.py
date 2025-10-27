"""PKCE (Proof Key for Code Exchange) utilities for OAuth 2.1.

This module implements RFC 7636 - Proof Key for Code Exchange by OAuth Public Clients.
PKCE is a security extension to OAuth 2.0 that prevents authorization code interception attacks.

References:
    - RFC 7636: https://datatracker.ietf.org/doc/html/rfc7636
    - OAuth 2.1 Draft: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-10
"""

import base64
import hashlib
import secrets
from typing import Tuple


def generate_code_verifier(length: int = 128) -> str:
    """
    Generate a cryptographically random code verifier.

    RFC 7636 Section 4.1: code_verifier = high-entropy cryptographic random STRING
    using the unreserved characters [A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~"
    with a minimum length of 43 characters and a maximum length of 128 characters.

    Args:
        length: Length of code verifier (43-128, default 128 for maximum entropy)

    Returns:
        URL-safe base64 encoded code verifier without padding

    Raises:
        ValueError: If length is not between 43 and 128

    Example:
        >>> verifier = generate_code_verifier()
        >>> len(verifier)
        128
        >>> all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~' for c in verifier)
        True
    """
    if not 43 <= length <= 128:
        raise ValueError(
            f"Code verifier length must be between 43 and 128, got {length}"
        )

    # Generate random bytes (length bytes for maximum entropy)
    # Using secrets module for cryptographically strong random numbers
    random_bytes = secrets.token_bytes(length)

    # Base64 URL-safe encode and remove padding
    # This produces characters from [A-Z] / [a-z] / [0-9] / "-" / "_"
    code_verifier = base64.urlsafe_b64encode(random_bytes).decode("utf-8")
    code_verifier = code_verifier.rstrip("=")

    # Ensure length is within bounds (base64 encoding may produce longer strings)
    return code_verifier[:length]


def generate_code_challenge(code_verifier: str, method: str = "S256") -> str:
    """
    Generate code challenge from code verifier.

    RFC 7636 Section 4.2:
    - S256: code_challenge = BASE64URL(SHA256(ASCII(code_verifier)))
    - plain: code_challenge = code_verifier

    OAuth 2.1 REQUIRES S256 method. The plain method is only for compatibility
    with legacy systems and should not be used in production.

    Args:
        code_verifier: The code verifier string
        method: Challenge method ("S256" or "plain", default "S256")

    Returns:
        Code challenge string

    Raises:
        ValueError: If method is not "S256" or "plain"

    Example:
        >>> verifier = generate_code_verifier()
        >>> challenge = generate_code_challenge(verifier, "S256")
        >>> len(challenge)
        43
        >>> challenge != verifier  # Challenge should be different from verifier
        True
    """
    if method == "S256":
        # SHA-256 hash of the code verifier
        digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
        # Base64 URL-safe encode and remove padding
        challenge = base64.urlsafe_b64encode(digest).decode("utf-8")
        return challenge.rstrip("=")
    elif method == "plain":
        # Plain method: challenge equals verifier
        # WARNING: This method is NOT recommended for OAuth 2.1
        return code_verifier
    else:
        raise ValueError(
            f"Unsupported code challenge method: {method}. " "Must be 'S256' or 'plain'"
        )


def generate_pkce_pair(length: int = 128, method: str = "S256") -> Tuple[str, str]:
    """
    Generate PKCE code verifier and challenge pair.

    This is a convenience function that generates both the code verifier
    and code challenge in one call.

    Args:
        length: Length of code verifier (43-128, default 128)
        method: Challenge method ("S256" or "plain", default "S256")

    Returns:
        Tuple of (code_verifier, code_challenge)

    Example:
        >>> verifier, challenge = generate_pkce_pair()
        >>> len(verifier)
        128
        >>> len(challenge)
        43
        >>> validate_code_verifier(verifier)
        True
    """
    code_verifier = generate_code_verifier(length)
    code_challenge = generate_code_challenge(code_verifier, method)
    return code_verifier, code_challenge


def validate_code_verifier(code_verifier: str) -> bool:
    """
    Validate code verifier format according to RFC 7636.

    RFC 7636 Section 4.1:
    - Minimum length: 43 characters
    - Maximum length: 128 characters
    - Allowed characters: [A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~"

    Args:
        code_verifier: Code verifier to validate

    Returns:
        True if valid, False otherwise

    Example:
        >>> validate_code_verifier("a" * 43)
        True
        >>> validate_code_verifier("a" * 128)
        True
        >>> validate_code_verifier("a" * 42)  # Too short
        False
        >>> validate_code_verifier("a" * 129)  # Too long
        False
        >>> validate_code_verifier("abc@123")  # Invalid character @
        False
    """
    if not code_verifier:
        return False

    length = len(code_verifier)
    if not 43 <= length <= 128:
        return False

    # Check allowed characters: [A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~"
    allowed_chars = set(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
    )
    return all(c in allowed_chars for c in code_verifier)


def validate_code_challenge(code_challenge: str, method: str = "S256") -> bool:
    """
    Validate code challenge format.

    Args:
        code_challenge: Code challenge to validate
        method: Challenge method ("S256" or "plain")

    Returns:
        True if valid, False otherwise

    Example:
        >>> verifier, challenge = generate_pkce_pair()
        >>> validate_code_challenge(challenge, "S256")
        True
    """
    if not code_challenge:
        return False

    if method == "S256":
        # S256 challenges are base64url encoded SHA-256 hashes (43 characters)
        if len(code_challenge) != 43:
            return False
        # Check base64url characters
        allowed_chars = set(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        )
        return all(c in allowed_chars for c in code_challenge)
    elif method == "plain":
        # Plain method uses the same validation as code verifier
        return validate_code_verifier(code_challenge)
    else:
        return False


def verify_code_challenge(
    code_verifier: str, code_challenge: str, method: str = "S256"
) -> bool:
    """
    Verify that a code verifier matches a code challenge.

    This is used by the authorization server to verify the PKCE flow.
    The client generates the verifier and challenge, sends the challenge
    in the authorization request, and sends the verifier in the token request.

    Args:
        code_verifier: The code verifier from token request
        code_challenge: The code challenge from authorization request
        method: Challenge method used ("S256" or "plain")

    Returns:
        True if verifier matches challenge, False otherwise

    Example:
        >>> verifier, challenge = generate_pkce_pair()
        >>> verify_code_challenge(verifier, challenge, "S256")
        True
        >>> verify_code_challenge("wrong_verifier", challenge, "S256")
        False
    """
    if not validate_code_verifier(code_verifier):
        return False

    if not validate_code_challenge(code_challenge, method):
        return False

    # Generate challenge from verifier and compare
    computed_challenge = generate_code_challenge(code_verifier, method)
    return computed_challenge == code_challenge


def generate_state(length: int = 32) -> str:
    """
    Generate a random state parameter for CSRF protection.

    The state parameter is used to prevent CSRF attacks in the OAuth flow.
    It should be a cryptographically random string that is stored in the
    client session and verified when the authorization callback is received.

    Args:
        length: Length of state string (default 32 bytes = 43 chars base64)

    Returns:
        URL-safe base64 encoded random state string

    Example:
        >>> state = generate_state()
        >>> len(state) >= 32
        True
    """
    return secrets.token_urlsafe(length)
