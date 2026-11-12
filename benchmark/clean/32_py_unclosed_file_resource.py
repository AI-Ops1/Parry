def read_token(fpath: str) -> str:
    with open(fpath, 'r', encoding='utf-8') as f:
        return f.read().strip()
