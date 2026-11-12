from datetime import datetime, timezone
def now_stamp():
    return datetime.now(timezone.utc)
