import asyncio
import socket
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from fastapi import FastAPI, Query, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from database import get_db_cursor, init_db
from paths import static_dir

app = FastAPI(title="Windows Event Log")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

_STATIC = static_dir()


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")


def _as_iso(value: Any) -> Optional[str]:
    if value is None:
        return None
    if hasattr(value, "isoformat"):
        return value.isoformat()
    return str(value)


@app.get("/system-info")
def get_system_info():
    hostname = socket.gethostname()
    try:
        local_ip = socket.gethostbyname(hostname)
    except Exception:
        local_ip = "Bilinmiyor"
    try:
        mac_num = uuid.getnode()
        mac_address = ":".join(f"{(mac_num >> ele) & 0xff:02x}" for ele in range(40, -1, -8))
    except Exception:
        mac_address = "Bilinmiyor"
    return {
        "hostname": hostname,
        "ip_address": local_ip,
        "mac_address": mac_address,
    }


@app.get("/")
def serve_dashboard():
    return FileResponse(_STATIC / "index.html")


app.mount("/static", StaticFiles(directory=str(_STATIC)), name="static")


def build_event_filters(
    level: Optional[str] = None,
    levels: Optional[str] = None,
    log_name: Optional[str] = None,
    category: Optional[str] = None,
    source: Optional[str] = None,
    event_id: Optional[int] = None,
    search: Optional[str] = None,
    error_code: Optional[str] = None,
    start: Optional[datetime] = None,
    end: Optional[datetime] = None,
):
    conditions = []
    params = []

    if levels:
        level_list = [x.strip() for x in levels.split(",") if x.strip()]
        if level_list:
            placeholders = ", ".join(["%s"] * len(level_list))
            conditions.append(f"level IN ({placeholders})")
            params.extend(level_list)
    elif level:
        conditions.append("level = %s")
        params.append(level)

    if log_name:
        conditions.append("log_name = %s")
        params.append(log_name)
    if category:
        conditions.append("category = %s")
        params.append(category)
    if source:
        conditions.append("source_name LIKE %s")
        params.append(f"%{source}%")
    if event_id is not None:
        conditions.append("event_id = %s")
        params.append(event_id)
    if error_code:
        conditions.append("error_code LIKE %s")
        params.append(f"%{error_code}%")
    if search:
        conditions.append(
            "(message LIKE %s OR description LIKE %s OR source_name LIKE %s OR CAST(event_id AS TEXT) LIKE %s)"
        )
        like = f"%{search}%"
        params.extend([like, like, like, like])
    if start:
        conditions.append("time_created >= %s")
        params.append(_iso(start) if isinstance(start, datetime) else start)
    if end:
        conditions.append("time_created <= %s")
        params.append(_iso(end) if isinstance(end, datetime) else end)

    where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    return where_clause, params


SELECT_FIELDS = """
    id, event_id, log_name, category, source_name, level, task, opcode,
    keywords, error_code, computer_name, user_sid, record_id,
    time_created, description, message, inserted_at
"""


@app.get("/events")
def get_events(
    level: Optional[str] = Query(None),
    levels: Optional[str] = Query(None, description="Virgulle: Critical,Error"),
    log_name: Optional[str] = Query(None),
    category: Optional[str] = Query(None),
    source: Optional[str] = Query(None),
    event_id: Optional[int] = Query(None),
    search: Optional[str] = Query(None),
    error_code: Optional[str] = Query(None),
    start: Optional[datetime] = Query(None),
    end: Optional[datetime] = Query(None),
    limit: int = Query(100, le=1000),
    offset: int = Query(0),
):
    where_clause, params = build_event_filters(
        level, levels, log_name, category, source, event_id, search, error_code, start, end
    )

    query = f"""
        SELECT {SELECT_FIELDS}
        FROM events
        {where_clause}
        ORDER BY time_created DESC
        LIMIT %s OFFSET %s
    """
    list_params = params + [limit, offset]

    with get_db_cursor() as cur:
        cur.execute(query, list_params)
        rows = cur.fetchall()
        count_query = f"SELECT COUNT(*) as total FROM events {where_clause}"
        cur.execute(count_query, params)
        total = cur.fetchone()["total"]

    return {"total": total, "count": len(rows), "events": rows}


@app.get("/events/{event_row_id}")
def get_event_detail(event_row_id: int):
    query = f"""
        SELECT {SELECT_FIELDS}, raw_xml
        FROM events
        WHERE id = %s
    """
    with get_db_cursor() as cur:
        cur.execute(query, [event_row_id])
        row = cur.fetchone()

    if not row:
        return {"error": "Event bulunamadi"}

    return row


@app.get("/stats/summary")
def get_summary(
    level: Optional[str] = None,
    levels: Optional[str] = None,
    log_name: Optional[str] = None,
    category: Optional[str] = None,
    source: Optional[str] = None,
    event_id: Optional[int] = None,
    search: Optional[str] = None,
    error_code: Optional[str] = None,
    start: Optional[datetime] = None,
    end: Optional[datetime] = None,
):
    where_clause, params = build_event_filters(
        level, levels, log_name, category, source, event_id, search, error_code, start, end
    )
    and_prefix = " AND " if where_clause else " WHERE "
    since_24h = _iso(_utc_now() - timedelta(hours=24))

    with get_db_cursor() as cur:
        cur.execute(f"SELECT COUNT(*) as total FROM events {where_clause}", params)
        total = cur.fetchone()["total"]

        cur.execute(
            f"""
            SELECT level, COUNT(*) as count
            FROM events
            {where_clause}
            GROUP BY level
            ORDER BY count DESC
            """,
            params,
        )
        by_level = cur.fetchall()

        cur.execute(
            f"""
            SELECT COUNT(*) as count FROM events
            {where_clause}{and_prefix}time_created >= %s
            """,
            params + [since_24h],
        )
        last_24h = cur.fetchone()["count"]

        cur.execute(
            f"""
            SELECT COUNT(*) as count FROM events
            {where_clause}{and_prefix}level IN ('Critical', 'Error')
              AND time_created >= %s
            """,
            params + [since_24h],
        )
        critical_last_24h = cur.fetchone()["count"]

        cur.execute(
            f"""
            SELECT event_id, source_name, level, COUNT(*) as count
            FROM events
            {where_clause}
            GROUP BY event_id, source_name, level
            ORDER BY count DESC
            LIMIT 5
            """,
            params,
        )
        top_events = cur.fetchall()

    return {
        "total_events": total,
        "last_24h": last_24h,
        "critical_or_error_last_24h": critical_last_24h,
        "by_level": by_level,
        "top_recurring_events": top_events,
    }


@app.get("/stats/timeline")
def get_timeline(
    hours: int = Query(24),
    bucket: str = Query("hour"),
    level: Optional[str] = None,
    levels: Optional[str] = None,
    log_name: Optional[str] = None,
    category: Optional[str] = None,
    source: Optional[str] = None,
    event_id: Optional[int] = None,
    search: Optional[str] = None,
    error_code: Optional[str] = None,
    start: Optional[datetime] = None,
    end: Optional[datetime] = None,
):
    where_clause, params = build_event_filters(
        level, levels, log_name, category, source, event_id, search, error_code, start, end
    )
    and_prefix = " AND " if where_clause else " WHERE "
    since = _iso(_utc_now() - timedelta(hours=int(hours)))

    if bucket == "hour":
        bucket_expr = "strftime('%Y-%m-%dT%H:00:00', time_created)"
    else:
        bucket_expr = "strftime('%Y-%m-%dT00:00:00', time_created)"

    query = f"""
        SELECT
            {bucket_expr} as bucket_time,
            level,
            COUNT(*) as count
        FROM events
        {where_clause}{and_prefix}time_created >= %s
        GROUP BY bucket_time, level
        ORDER BY bucket_time ASC
    """

    with get_db_cursor() as cur:
        cur.execute(query, params + [since])
        rows = cur.fetchall()

    return {"bucket": bucket, "hours": hours, "data": rows}


@app.get("/stats/by-log")
def get_by_log(
    level: Optional[str] = None,
    levels: Optional[str] = None,
    log_name: Optional[str] = None,
    category: Optional[str] = None,
    source: Optional[str] = None,
    event_id: Optional[int] = None,
    search: Optional[str] = None,
    error_code: Optional[str] = None,
    start: Optional[datetime] = None,
    end: Optional[datetime] = None,
):
    where_clause, params = build_event_filters(
        level, levels, log_name, category, source, event_id, search, error_code, start, end
    )
    query = f"""
        SELECT log_name, category, COUNT(*) as count
        FROM events
        {where_clause}
        GROUP BY log_name, category
        ORDER BY count DESC
    """
    with get_db_cursor() as cur:
        cur.execute(query, params)
        rows = cur.fetchall()
    return {"data": rows}


@app.get("/stats/top-events")
def get_top_events(
    limit: int = Query(10, le=30),
    level: Optional[str] = None,
    levels: Optional[str] = None,
    log_name: Optional[str] = None,
    category: Optional[str] = None,
    source: Optional[str] = None,
    event_id: Optional[int] = None,
    search: Optional[str] = None,
    error_code: Optional[str] = None,
    start: Optional[datetime] = None,
    end: Optional[datetime] = None,
):
    where_clause, params = build_event_filters(
        level, levels, log_name, category, source, event_id, search, error_code, start, end
    )
    query = f"""
        SELECT event_id, source_name, level, category, COUNT(*) as count
        FROM events
        {where_clause}
        GROUP BY event_id, source_name, level, category
        ORDER BY count DESC
        LIMIT %s
    """
    with get_db_cursor() as cur:
        cur.execute(query, params + [limit])
        rows = cur.fetchall()
    return {"data": rows}


@app.get("/stats/day-comparison")
def get_day_comparison(
    level: Optional[str] = None,
    levels: Optional[str] = None,
    log_name: Optional[str] = None,
    category: Optional[str] = None,
    source: Optional[str] = None,
    event_id: Optional[int] = None,
    search: Optional[str] = None,
    error_code: Optional[str] = None,
):
    where_clause, params = build_event_filters(
        level, levels, log_name, category, source, event_id, search, error_code, None, None
    )
    since_24h = _iso(_utc_now() - timedelta(hours=24))
    since_48h = _iso(_utc_now() - timedelta(hours=48))

    query = f"""
        SELECT
            SUM(CASE WHEN time_created >= %s THEN 1 ELSE 0 END) as today,
            SUM(CASE
                WHEN time_created >= %s AND time_created < %s THEN 1
                ELSE 0
            END) as yesterday
        FROM events
        {where_clause}
    """

    with get_db_cursor() as cur:
        cur.execute(query, [since_24h, since_48h, since_24h] + params)
        row = cur.fetchone()

    today = row["today"] or 0
    yesterday = row["yesterday"] or 0
    pct_change = None if yesterday == 0 else round(((today - yesterday) / yesterday) * 100, 1)

    return {
        "today": today,
        "yesterday": yesterday,
        "pct_change": pct_change,
        "today_start": (_utc_now() - timedelta(hours=24)).isoformat(),
        "yesterday_start": (_utc_now() - timedelta(hours=48)).isoformat(),
        "yesterday_end": (_utc_now() - timedelta(hours=24)).isoformat(),
    }


@app.get("/stats/compare")
def get_compare(
    period: str = Query("today_vs_yesterday", description="today_vs_yesterday"),
    level: Optional[str] = None,
    levels: Optional[str] = None,
    log_name: Optional[str] = None,
    category: Optional[str] = None,
    source: Optional[str] = None,
    event_id: Optional[int] = None,
    search: Optional[str] = None,
    error_code: Optional[str] = None,
):
    where_clause, params = build_event_filters(
        level, levels, log_name, category, source, event_id, search, error_code, None, None
    )
    and_prefix = " AND " if where_clause else " WHERE "
    since_24h = _iso(_utc_now() - timedelta(hours=24))
    since_48h = _iso(_utc_now() - timedelta(hours=48))

    query = f"""
        SELECT period, level, log_name, COUNT(*) as count
        FROM (
            SELECT
                CASE
                    WHEN time_created >= %s THEN 'today'
                    WHEN time_created >= %s AND time_created < %s THEN 'yesterday'
                END as period,
                level,
                log_name
            FROM events
            {where_clause}{and_prefix}time_created >= %s
        ) t
        WHERE period IS NOT NULL
        GROUP BY period, level, log_name
        ORDER BY period, count DESC
    """

    with get_db_cursor() as cur:
        cur.execute(query, [since_24h, since_48h, since_24h] + params + [since_48h])
        rows = cur.fetchall()

        cur.execute(
            f"""
            SELECT
                SUM(CASE WHEN time_created >= %s THEN 1 ELSE 0 END) as today,
                SUM(CASE
                    WHEN time_created >= %s AND time_created < %s THEN 1
                    ELSE 0
                END) as yesterday
            FROM events
            {where_clause}
            """,
            [since_24h, since_48h, since_24h] + params,
        )
        totals = cur.fetchone()

    return {
        "period": period,
        "totals": {
            "today": totals["today"] or 0,
            "yesterday": totals["yesterday"] or 0,
        },
        "breakdown": rows,
    }


@app.get("/stats/by-source")
def get_by_source(
    limit: int = Query(10, le=50),
    level: Optional[str] = None,
    levels: Optional[str] = None,
    log_name: Optional[str] = None,
    category: Optional[str] = None,
    source: Optional[str] = None,
    event_id: Optional[int] = None,
    search: Optional[str] = None,
    error_code: Optional[str] = None,
    start: Optional[datetime] = None,
    end: Optional[datetime] = None,
):
    where_clause, params = build_event_filters(
        level, levels, log_name, category, source, event_id, search, error_code, start, end
    )
    query = f"""
        SELECT source_name, log_name, category, COUNT(*) as count
        FROM events
        {where_clause}
        GROUP BY source_name, log_name, category
        ORDER BY count DESC
        LIMIT %s
    """
    with get_db_cursor() as cur:
        cur.execute(query, params + [limit])
        rows = cur.fetchall()
    return {"data": rows}


class ConnectionManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        dead = []
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception:
                dead.append(connection)
        for d in dead:
            self.disconnect(d)


manager = ConnectionManager()


@app.websocket("/ws/live")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)


async def poll_and_broadcast_new_events():
    last_sent_id = 0
    with get_db_cursor() as cur:
        cur.execute("SELECT COALESCE(MAX(id), 0) as max_id FROM events")
        last_sent_id = cur.fetchone()["max_id"]

    while True:
        await asyncio.sleep(2)
        if not manager.active_connections:
            continue

        with get_db_cursor() as cur:
            cur.execute(
                f"""
                SELECT {SELECT_FIELDS}
                FROM events
                WHERE id > %s
                ORDER BY id ASC
                """,
                [last_sent_id],
            )
            new_rows = cur.fetchall()

        if new_rows:
            last_sent_id = max(row["id"] for row in new_rows)
            for row in new_rows:
                row["time_created"] = _as_iso(row["time_created"])
                if row.get("inserted_at"):
                    row["inserted_at"] = _as_iso(row["inserted_at"])
                await manager.broadcast({"type": "new_event", "data": row})


@app.on_event("startup")
async def startup_event():
    init_db()
    asyncio.create_task(poll_and_broadcast_new_events())
