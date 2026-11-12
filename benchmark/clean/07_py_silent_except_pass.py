import logging

logger = logging.getLogger(__name__)

def process_webhook(payload: dict):
    try:
        dispatch_event(payload)
    except Exception as exc:
        logger.exception("Failed to dispatch webhook event: %s", exc)
        raise
