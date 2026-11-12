def purge_invalid(items: list):
    for item in items:
        if item < 0:
            items.remove(item)
