
import time
import logging
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

import win32evtlog
import win32security
import win32api

from database import get_connection, init_db

LOG_NAMES = ["System", "Application", "Security"]
POLL_INTERVAL_SECONDS = 5

CATEGORY_MAP = {
    "System": "Sistem",
    "Application": "Uygulama",
    "Security": "Güvenlik",
}

LEVEL_MAP = {
    1: "Critical",
    2: "Error",
    3: "Warning",
    4: "Information",
    5: "Verbose",
}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("collector")


def enable_security_privilege():
    try:
        htoken = win32security.OpenProcessToken(
            win32api.GetCurrentProcess(),
            win32security.TOKEN_ADJUST_PRIVILEGES | win32security.TOKEN_QUERY,
        )
        privilege_id = win32security.LookupPrivilegeValue(None, "SeSecurityPrivilege")
        win32security.AdjustTokenPrivileges(
            htoken, False, [(privilege_id, win32security.SE_PRIVILEGE_ENABLED)]
        )
        logger.info("SeSecurityPrivilege etkinlestirildi.")
    except Exception as e:
        logger.warning(f"SeSecurityPrivilege etkinlestirilemedi: {e}")


def _to_iso(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")


def _parse_iso(value) -> datetime:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value
    text = str(value).replace("Z", "+00:00")
    if "T" in text:
        try:
            dt = datetime.fromisoformat(text)
        except ValueError:
            dt = datetime.strptime(text[:19], "%Y-%m-%dT%H:%M:%S")
    else:
        dt = datetime.strptime(text[:19], "%Y-%m-%d %H:%M:%S")
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def insert_events(conn, events: list[dict]):
    if not events:
        return

    query = """
        INSERT OR IGNORE INTO events
            (event_id, log_name, category, source_name, level, task, opcode,
             keywords, error_code, computer_name, user_sid, record_id,
             time_created, description, message, raw_xml)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """
    values = [
        (
            e["event_id"],
            e["log_name"],
            e["category"],
            e["source_name"],
            e["level"],
            e["task"],
            e["opcode"],
            e["keywords"],
            e["error_code"],
            e["computer_name"],
            e["user_sid"],
            e["record_id"],
            _to_iso(e["time_created"]) if isinstance(e["time_created"], datetime) else e["time_created"],
            e["description"],
            e["message"],
            e["raw_xml"],
        )
        for e in events
    ]

    conn.executemany(query, values)
    conn.commit()
    logger.info(f"{len(values)} event veritabanina yazildi.")


def format_event_message(event_handle) -> str:
    """Windows'un formatlanmis aciklama metnini dener."""
    try:
        return win32evtlog.EvtFormatMessage(
            None, event_handle, win32evtlog.EvtFormatMessageEvent
        )
    except Exception:
        return ""


def read_new_events(log_name: str, after_time: datetime) -> list[dict]:
    results = []
    try:
        query = win32evtlog.EvtQuery(
            log_name,
            win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryReverseDirection,
            "*",
        )
    except Exception as e:
        logger.error(f"'{log_name}' logu acilamadi: {e}")
        return results

    while True:
        events = win32evtlog.EvtNext(query, 50)
        if not events:
            break

        stop = False
        for event in events:
            xml_content = win32evtlog.EvtRender(event, win32evtlog.EvtRenderEventXml)
            description = format_event_message(event)
            parsed = parse_event_xml(xml_content, log_name, description)

            if parsed is None:
                continue

            if parsed["time_created"] <= after_time:
                stop = True
                break

            results.append(parsed)

        if stop:
            break

    return results


def _text(el, default=""):
    if el is None or el.text is None:
        return default
    return el.text


def extract_error_code(root, ns, message: str, description: str) -> str | None:
    """EventData / System icinden olasi hata kodunu cikar."""
    system = root.find("e:System", ns)
    if system is not None:
        for tag in ("e:Execution",):
            ex = system.find(tag, ns)
            if ex is not None:
                # ProcessID vb. hata kodu degil
                pass

    event_data = root.find("e:EventData", ns)
    if event_data is not None:
        for data in event_data.findall("e:Data", ns):
            name = (data.attrib.get("Name") or "").lower()
            text = (data.text or "").strip()
            if not text:
                continue
            if any(k in name for k in ("status", "error", "result", "hresult", "ntstatus", "failure")):
                return text[:64]
            if re.fullmatch(r"0x[0-9a-fA-F]+", text) or re.fullmatch(r"\d{1,10}", text):
                if "code" in name or "status" in name or "error" in name:
                    return text[:64]

    combined = f"{description or ''}\n{message or ''}"
    m = re.search(r"(?:0x[0-9a-fA-F]{2,8}|HRESULT\s*[:=]?\s*0x[0-9a-fA-F]+)", combined, re.I)
    if m:
        return m.group(0)[:64]
    return None


def parse_event_xml(xml_str: str, log_name: str, description: str = "") -> dict | None:
    try:
        ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
        root = ET.fromstring(xml_str)
        system = root.find("e:System", ns)

        event_id = int(system.find("e:EventID", ns).text)
        level_el = system.find("e:Level", ns)
        level_num = int(level_el.text) if level_el is not None and level_el.text else 4
        computer = _text(system.find("e:Computer", ns), "Unknown")

        time_str = system.find("e:TimeCreated", ns).attrib["SystemTime"]
        time_created = datetime.strptime(
            time_str.split(".")[0], "%Y-%m-%dT%H:%M:%S"
        ).replace(tzinfo=timezone.utc)

        provider_el = system.find("e:Provider", ns)
        source_name = provider_el.attrib.get("Name", "Unknown") if provider_el is not None else "Unknown"

        task = _text(system.find("e:Task", ns))
        opcode = _text(system.find("e:Opcode", ns))
        keywords = system.find("e:Keywords", ns)
        keywords_val = keywords.text if keywords is not None else None

        record_el = system.find("e:EventRecordID", ns)
        record_id = int(record_el.text) if record_el is not None and record_el.text else None

        security = system.find("e:Security", ns)
        user_sid = security.attrib.get("UserID") if security is not None else None

        message = extract_message_text(root, ns)
        if not description:
            description = message

        error_code = extract_error_code(root, ns, message, description)

        return {
            "event_id": event_id,
            "log_name": log_name,
            "category": CATEGORY_MAP.get(log_name, log_name),
            "source_name": source_name,
            "level": LEVEL_MAP.get(level_num, "Unknown"),
            "task": task or None,
            "opcode": opcode or None,
            "keywords": keywords_val,
            "error_code": error_code,
            "computer_name": computer,
            "user_sid": user_sid,
            "record_id": record_id,
            "time_created": time_created,
            "description": description,
            "message": message,
            "raw_xml": xml_str,
        }
    except Exception as e:
        logger.warning(f"XML parse hatasi: {e}")
        return None


def extract_message_text(root, ns) -> str:
    event_data = root.find("e:EventData", ns)
    if event_data is None:
        # UserData alternatif
        user_data = root.find("e:UserData", ns)
        if user_data is None:
            return ""
        parts = []
        for child in list(user_data.iter()):
            if child.text and child.text.strip():
                tag = child.tag.split("}")[-1] if "}" in child.tag else child.tag
                parts.append(f"{tag}: {child.text.strip()}")
        return " | ".join(parts[:40])

    parts = []
    for data in event_data.findall("e:Data", ns):
        name = data.attrib.get("Name", "")
        text = data.text or ""
        parts.append(f"{name}: {text}" if name else text)

    return " | ".join(parts)


def get_resume_time(conn) -> datetime:
    """
    DB'deki en son event zamanindan devam et.
    Collector kapaliyken gelen event'ler kacmasin.
    Tablo bossa 'simdi'den basla.
    """
    row = conn.execute("SELECT MAX(time_created) AS max_ts FROM events").fetchone()
    if row and row["max_ts"] is not None:
        return _parse_iso(row["max_ts"])
    return datetime.now(timezone.utc)


def main():
    logger.info("Collector baslatiliyor...")
    enable_security_privilege()
    init_db()
    conn = get_connection()

    last_check_time = get_resume_time(conn)
    logger.info(f"Kaldigi yerden devam: {last_check_time.isoformat()}")

    try:
        while True:
            all_new_events = []

            for log_name in LOG_NAMES:
                new_events = read_new_events(log_name, last_check_time)
                all_new_events.extend(new_events)

            if all_new_events:
                latest_time = max(e["time_created"] for e in all_new_events)
                last_check_time = latest_time
                insert_events(conn, all_new_events)
            else:
                logger.debug("Yeni event yok.")

            time.sleep(POLL_INTERVAL_SECONDS)

    except KeyboardInterrupt:
        logger.info("Collector durduruluyor...")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
