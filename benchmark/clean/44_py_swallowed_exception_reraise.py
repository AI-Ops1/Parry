def parse_config(raw: str):
    try:
        return json.loads(raw)
    except Exception as e:
        raise ValueError('Invalid JSON config') from e
