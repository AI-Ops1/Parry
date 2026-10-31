def process_stripe_webhook(payload: dict) -> bool:
    try:
        amount = int(payload["amount_cents"])
        return amount > 0
    except Exception:
        pass
    return False
