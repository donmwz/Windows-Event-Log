"""
Windows Event Log — tek tikla baslatici (gomulu SQLite).

1) SQLite veritabani
2) FastAPI dashboard
3) Event collector
4) Tarayiciyi acar
"""
from __future__ import annotations

import configparser
import multiprocessing
import os
import shutil
import threading
import time
import traceback
import webbrowser

from paths import app_dir, config_path, resource_dir


def _load_app_settings() -> dict:
    host = "127.0.0.1"
    port = 8000
    open_browser = True
    path = config_path()
    if path.exists():
        parser = configparser.ConfigParser()
        parser.read(path, encoding="utf-8")
        if parser.has_section("app"):
            host = parser.get("app", "host", fallback=host)
            port = parser.getint("app", "port", fallback=port)
            open_browser = parser.getboolean("app", "open_browser", fallback=True)
    return {"host": host, "port": port, "open_browser": open_browser}


def _ensure_sidecar_files() -> None:
    dest = app_dir()
    src = resource_dir()
    for name in ("config.ini", "schema_sqlite.sql"):
        target = dest / name
        source = src / name
        if not target.exists() and source.exists():
            shutil.copy2(source, target)


def _run_api(host: str, port: int) -> None:
    import uvicorn
    from main import app

    uvicorn.run(app, host=host, port=port, log_level="info")


def _run_collector() -> None:
    import collector

    collector.main()


def main() -> int:
    multiprocessing.freeze_support()
    os.chdir(app_dir())
    _ensure_sidecar_files()

    settings = _load_app_settings()
    host = settings["host"]
    port = settings["port"]
    url = f"http://{host}:{port}"

    print("=" * 56)
    print("  Windows Event Log Monitor")
    print("=" * 56)
    print(f"  Klasor : {app_dir()}")
    print(f"  Panel  : {url}")
    print("  Durdur : Ctrl+C")
    print("=" * 56)

    from database import init_db, db_path

    db = init_db()
    print(f"[*] SQLite: {db}")

    api_thread = threading.Thread(
        target=_run_api, args=(host, port), name="api", daemon=True
    )
    api_thread.start()

    collector_proc = multiprocessing.Process(
        target=_run_collector, name="collector", daemon=True
    )
    collector_proc.start()

    time.sleep(1.5)
    if settings["open_browser"]:
        try:
            webbrowser.open(url)
        except Exception:
            pass

    print(f"\n[OK] Sistem calisiyor → {url}")
    print("     Security loglari icin bu programi Yonetici olarak calistirin.\n")

    try:
        while True:
            if not api_thread.is_alive():
                print("[HATA] API durdu.")
                break
            if not collector_proc.is_alive():
                print("[!] Collector durdu, yeniden baslatiliyor...")
                collector_proc = multiprocessing.Process(
                    target=_run_collector, name="collector", daemon=True
                )
                collector_proc.start()
            time.sleep(2)
    except KeyboardInterrupt:
        print("\n[*] Kapatiliyor...")
    finally:
        if collector_proc.is_alive():
            collector_proc.terminate()
            collector_proc.join(timeout=5)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception:
        traceback.print_exc()
        input("\nBeklenmeyen hata. Enter...")
        raise SystemExit(1)
