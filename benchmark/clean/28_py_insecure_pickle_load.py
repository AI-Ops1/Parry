import json
def parse_user_session(cookie_bytes: bytes):
    return json.loads(cookie_bytes.decode('utf-8'))
