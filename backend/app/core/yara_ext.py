"""
YARA 外部变量工具

提供统一的默认 external 变量以及基于文件路径/名称动态构建 external 的辅助函数。
"""

from __future__ import annotations

from pathlib import Path
from typing import Dict, Optional, Union


ExternalPath = Union[str, Path, None]

# 默认 external 变量集合，确保各个编译流程一致
DEFAULT_EXTERNALS = {
    "filename": "",
    "filepath": "",
    "extension": "",
    "filesize": 0,
    "sha256": "",
    "filetype": "",
}


def get_default_externals() -> Dict[str, str]:
    """返回一份 default externals 的浅拷贝，供 yara.compile 使用。"""
    return dict(DEFAULT_EXTERNALS)


def build_externals(
    *,
    filename: Optional[str] = None,
    filepath: ExternalPath = None,
    data: Optional[bytes] = None,
) -> Dict[str, str]:
    """
    根据文件名/路径构建 external 变量，确保运行时匹配时能够访问 filename/filepath/extension。
    """
    externals = get_default_externals()

    path_obj: Optional[Path] = None
    if filepath:
        path_obj = Path(filepath)
        externals["filepath"] = path_obj.as_posix()
        if not filename:
            filename = path_obj.name

    if filename:
        externals["filename"] = filename
        externals["extension"] = Path(filename).suffix
        externals["filetype"] = externals["extension"].lstrip('.')
    elif path_obj:
        externals["extension"] = path_obj.suffix
        externals["filetype"] = path_obj.suffix.lstrip('.')

    if data is not None:
        externals["filesize"] = len(data)
        try:
            import hashlib
            externals["sha256"] = hashlib.sha256(data).hexdigest()
        except Exception:
            externals["sha256"] = ""

    return externals


