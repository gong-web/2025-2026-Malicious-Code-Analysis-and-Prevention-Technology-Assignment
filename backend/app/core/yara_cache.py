from pathlib import Path
import hashlib
import yara


def _hash_sources(sources: dict) -> str:
    h = hashlib.sha256()
    for name in sorted(sources.keys()):
        h.update(name.encode())
        h.update(hashlib.sha256(sources[name].encode()).digest())
    return h.hexdigest()


def get_cache_path(compiled_dir: Path, group_key: str, sources: dict) -> Path:
    digest = _hash_sources(sources)
    compiled_dir.mkdir(parents=True, exist_ok=True)
    return compiled_dir / f"yara_{group_key}_{digest}.yarac"


def try_load(cache_path: Path):
    if cache_path.exists():
        return yara.load(str(cache_path))
    return None


def save(compiled_rules, cache_path: Path):
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    compiled_rules.save(str(cache_path))