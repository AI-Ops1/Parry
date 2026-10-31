def record_login_failure(user_id: str, attempts=[]):
    attempts.append(user_id)
    return attempts
