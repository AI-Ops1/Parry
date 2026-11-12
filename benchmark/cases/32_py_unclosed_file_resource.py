def read_token(fpath: str) -> str:
    f = open(fpath, 'r')
    return f.read().strip()
