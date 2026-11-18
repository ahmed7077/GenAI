import jwt

from app.security import create_access_token, decode_access_token, hash_password, verify_password


def test_passwords_are_argon2_hashed_and_verified() -> None:
    password_hash = hash_password("Strong-password-123")

    assert password_hash.startswith("$argon2")
    assert verify_password("Strong-password-123", password_hash)
    assert not verify_password("incorrect", password_hash)


def test_access_token_round_trip() -> None:
    token = create_access_token("user-123", "analyst")

    assert decode_access_token(token)["sub"] == "user-123"

    try:
        decode_access_token(token + "tampered")
    except jwt.PyJWTError:
        pass
    else:
        raise AssertionError("Tampered JWT was accepted")
