"""Kurulu / PyInstaller ortaminda dosya yollari."""
from __future__ import annotations

import sys
from pathlib import Path


def is_frozen() -> bool:
    return getattr(sys, "frozen", False)


def app_dir() -> Path:
    """Exe veya proje kok dizini (yazilabilir yan dosyalar: config.ini)."""
    if is_frozen():
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


def resource_dir() -> Path:
    """Paketlenmis kaynaklar (static, sql, compose)."""
    if is_frozen():
        meipass = getattr(sys, "_MEIPASS", None)
        if meipass:
            return Path(meipass)
        return app_dir()
    return Path(__file__).resolve().parent


def static_dir() -> Path:
    return resource_dir() / "static"


def config_path() -> Path:
    return app_dir() / "config.ini"
