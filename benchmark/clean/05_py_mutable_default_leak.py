def record_login(user_id: str, attempts: list | None = None) -> list:
    if attempts is None:
        attempts = []
    attempts.append(user_id)
    return attempts
