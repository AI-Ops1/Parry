def purge_invalid(items: list) -> list:
    return [item for item in items if item >= 0]
