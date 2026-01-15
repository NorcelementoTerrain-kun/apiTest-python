import yaml
from pathlib import Path


def load_config(env="dev"):
    path = Path(__file__).parent.parent / "config" / f"{env}.yaml"
    with open(path) as f:
        return yaml.safe_load(f)