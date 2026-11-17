"""JWTProvider against the real PyJWT: the only place the gateway decodes JWTs."""

from __future__ import annotations

import base64
import hashlib
import hmac
import time

import jwt
import pytest

from secure_mcp_gateway.plugins.auth.base import AuthCredentials, AuthStatus
from secure_mcp_gateway.plugins.auth.example_providers import JWTProvider

SECRET = "jwt-provider-test-secret-of-at-least-32-bytes"
OTHER_SECRET = "a-different-secret-also-at-least-32-bytes!!"


def _token(
    claims: dict | None = None, secret: str = SECRET, algorithm: str = "HS256"
) -> str:
    payload = {"sub": "user-1", "exp": int(time.time()) + 300}
    payload.update(claims or {})
    return jwt.encode(payload, secret, algorithm=algorithm)


async def _auth(provider: JWTProvider, token: str):
    return await provider.authenticate(AuthCredentials(access_token=token))


async def test_valid_token_authenticates_and_exposes_claims():
    result = await _auth(JWTProvider(SECRET), _token({"role": "admin"}))

    assert result.status == AuthStatus.SUCCESS
    assert result.authenticated is True
    assert result.user_id == "user-1"
    assert result.metadata["jwt_payload"]["role"] == "admin"
    assert result.metadata["provider"] == "jwt"


async def test_user_id_claim_is_used_when_sub_is_absent():
    token = jwt.encode(
        {"user_id": "user-2", "exp": int(time.time()) + 300}, SECRET, algorithm="HS256"
    )

    result = await _auth(JWTProvider(SECRET), token)

    assert result.status == AuthStatus.SUCCESS
    assert result.user_id == "user-2"


async def test_api_key_field_is_accepted_as_the_token():
    result = await JWTProvider(SECRET).authenticate(AuthCredentials(api_key=_token()))

    assert result.status == AuthStatus.SUCCESS


async def test_missing_token_is_rejected():
    result = await JWTProvider(SECRET).authenticate(AuthCredentials())

    assert result.status == AuthStatus.INVALID_CREDENTIALS
    assert result.authenticated is False


async def test_expired_token_maps_to_expired():
    result = await _auth(JWTProvider(SECRET), _token({"exp": int(time.time()) - 60}))

    assert result.status == AuthStatus.EXPIRED
    assert result.authenticated is False


async def test_expired_token_is_accepted_when_verify_exp_is_off():
    provider = JWTProvider(SECRET, verify_exp=False)

    result = await _auth(provider, _token({"exp": int(time.time()) - 60}))

    assert result.status == AuthStatus.SUCCESS


async def test_wrong_signature_is_rejected():
    result = await _auth(JWTProvider(SECRET), _token(secret=OTHER_SECRET))

    assert result.status == AuthStatus.INVALID_CREDENTIALS
    assert result.authenticated is False


async def test_tampered_payload_is_rejected():
    header, _, signature = _token().split(".")
    forged_payload = _token({"sub": "attacker"}, secret=OTHER_SECRET).split(".")[1]

    result = await _auth(JWTProvider(SECRET), f"{header}.{forged_payload}.{signature}")

    assert result.status == AuthStatus.INVALID_CREDENTIALS


async def test_unsigned_alg_none_token_is_rejected():
    unsigned = jwt.encode({"sub": "attacker"}, key=None, algorithm="none")

    result = await _auth(JWTProvider(SECRET), unsigned)

    assert result.status == AuthStatus.INVALID_CREDENTIALS


async def test_algorithm_outside_the_allow_list_is_rejected():
    token = _token(algorithm="HS512")

    result = await _auth(JWTProvider(SECRET, algorithm="HS256"), token)

    assert result.status == AuthStatus.INVALID_CREDENTIALS


async def test_garbage_token_is_rejected_not_raised():
    result = await _auth(JWTProvider(SECRET), "not-a-jwt")

    assert result.status == AuthStatus.INVALID_CREDENTIALS


@pytest.mark.parametrize(
    ("claims", "accepted"),
    [
        ({"aud": "gateway", "iss": "enkrypt"}, True),
        ({"aud": "someone-else", "iss": "enkrypt"}, False),
        ({"aud": "gateway", "iss": "someone-else"}, False),
        ({"iss": "enkrypt"}, False),
    ],
)
async def test_audience_and_issuer_are_enforced(claims, accepted):
    provider = JWTProvider(SECRET, audience="gateway", issuer="enkrypt")

    result = await _auth(provider, _token(claims))

    assert (result.status == AuthStatus.SUCCESS) is accepted


async def test_signature_check_off_still_decodes_claims():
    provider = JWTProvider("ignored", verify_signature=False)

    result = await _auth(provider, _token({"role": "viewer"}, secret=OTHER_SECRET))

    assert result.status == AuthStatus.SUCCESS
    assert result.metadata["jwt_payload"]["role"] == "viewer"


async def test_unverified_peek_does_not_weaken_a_later_verified_decode():
    peek = JWTProvider("ignored", verify_signature=False, verify_exp=False)
    strict = JWTProvider(SECRET)
    expired = _token({"exp": int(time.time()) - 60})

    assert (await _auth(peek, expired)).status == AuthStatus.SUCCESS
    assert (await _auth(strict, expired)).status == AuthStatus.EXPIRED


async def test_rs256_public_key_verifies_and_hmac_confusion_is_rejected():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_pem = (
        private_key.public_key()
        .public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        .decode()
    )

    rs256 = JWTProvider(public_pem, algorithm="RS256")
    assert (
        await _auth(rs256, _token(secret=private_key, algorithm="RS256"))
    ).status == (AuthStatus.SUCCESS)

    header = _b64url(b'{"alg":"HS256","typ":"JWT"}')
    payload = _b64url(b'{"sub":"attacker"}')
    signing_input = f"{header}.{payload}".encode()
    signature = _b64url(
        hmac.new(public_pem.encode(), signing_input, hashlib.sha256).digest()
    )
    forged = f"{header}.{payload}.{signature}"

    hs256_with_public_key = JWTProvider(public_pem, algorithm="HS256")
    assert (await _auth(hs256_with_public_key, forged)).authenticated is False


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
