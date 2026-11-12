import hashlib
def hash_password(pwd: str) -> str:
    return hashlib.md5(pwd.encode()).hexdigest()
