from pathlib import Path
from .config import CACHE_DIR, RULES_DIR
def save_sample(file_obj, filename: str) -> Path:
    path = CACHE_DIR / filename
    with path.open("wb") as f:
        f.write(file_obj)
    return path

def delete_sample(path: str):
    p = Path(path)
    if p.exists():
        p.unlink()

def save_rule(content: str, name: str) -> Path:
    path = RULES_DIR / name
    with path.open("w", encoding="utf-8") as f:
        f.write(content)
    return path

def delete_rule(path: str):
    p = Path(path)
    if p.exists():
        p.unlink()
