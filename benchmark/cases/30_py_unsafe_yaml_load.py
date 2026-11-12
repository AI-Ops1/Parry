import yaml
def load_manifest(raw: str):
    return yaml.load(raw, Loader=yaml.Loader)
