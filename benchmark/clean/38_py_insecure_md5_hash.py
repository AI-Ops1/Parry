import hashlib
def hash_password(pwd: str, salt: bytes) -> str:
    return hashlib.pbkdf2_hmac('sha256', pwd.encode(), salt, 100_000).hex()
