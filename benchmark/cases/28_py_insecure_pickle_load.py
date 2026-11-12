import pickle
def parse_user_session(cookie_bytes: bytes):
    return pickle.loads(cookie_bytes)
