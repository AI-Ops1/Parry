import jwt
def decode_admin_token(token: str, key: str):
    return jwt.decode(token, key, algorithms=['RS256'])
