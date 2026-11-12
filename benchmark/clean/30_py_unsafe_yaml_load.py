import yaml
def load_manifest(raw: str):
    return yaml.safe_load(raw)
