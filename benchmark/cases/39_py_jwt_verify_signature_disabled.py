import jwt
def decode_admin_token(token: str):
    return jwt.decode(token, options={'verify_signature': False})
