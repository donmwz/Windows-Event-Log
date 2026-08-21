import asyncio
import socket
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import FastAPI, Query, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from database import get_db_cursor

app = FastAPI(title="Windows Event Log")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


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
    return FileResponse("static/index.html")


app.mount("/static", StaticFiles(directory="static"), name="static")


# --------------------------------------------------------------------------
# Ortak filtre yardimcilari (tum dashboard sorgularinda kullanilir)
# --------------------------------------------------------------------------

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
        conditions.append("source_name ILIKE %s")
        params.append(f"%{source}%")
    if event_id is not None:
        conditions.append("event_id = %s")
        params.append(event_id)
    if error_code:
        conditions.append("error_code ILIKE %s")
        params.append(f"%{error_code}%")
    if search:
        conditions.append(
            "(message ILIKE %s OR description ILIKE %s OR source_name ILIKE %s OR CAST(event_id AS TEXT) ILIKE %s)"
        )
        like = f"%{search}%"
        params.extend([like, like, like, like])
    if start:
        conditions.append("time_created >= %s")
        params.append(start)
    if end:
        conditions.append("time_created <= %s")
        params.append(end)

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
            {where_clause}{and_prefix}time_created >= NOW() - INTERVAL '24 hours'
            """,
            params,
        )
        last_24h = cur.fetchone()["count"]

        cur.execute(
            f"""
            SELECT COUNT(*) as count FROM events
            {where_clause}{and_prefix}level IN ('Critical', 'Error')
              AND time_created >= NOW() - INTERVAL '24 hours'
            """,
            params,
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
    trunc_unit = "hour" if bucket == "hour" else "day"
    where_clause, params = build_event_filters(
        level, levels, log_name, category, source, event_id, search, error_code, start, end
    )
    and_prefix = " AND " if where_clause else " WHERE "

    query = f"""
        SELECT
            date_trunc('{trunc_unit}', time_created) as bucket_time,
            level,
            COUNT(*) as count
        FROM events
        {where_clause}{and_prefix}time_created >= NOW() - INTERVAL '{int(hours)} hours'
        GROUP BY bucket_time, level
        ORDER BY bucket_time ASC
    """

    with get_db_cursor() as cur:
        cur.execute(query, params)
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

    query = f"""
        SELECT
            COUNT(*) FILTER (
                WHERE time_created >= NOW() - INTERVAL '24 hours'
            ) as today,
            COUNT(*) FILTER (
                WHERE time_created >= NOW() - INTERVAL '48 hours'
                  AND time_created < NOW() - INTERVAL '24 hours'
            ) as yesterday
        FROM events
        {where_clause}
    """

    with get_db_cursor() as cur:
        cur.execute(query, params)
        row = cur.fetchone()

    today = row["today"] or 0
    yesterday = row["yesterday"] or 0
    pct_change = None if yesterday == 0 else round(((today - yesterday) / yesterday) * 100, 1)

    return {
        "today": today,
        "yesterday": yesterday,
        "pct_change": pct_change,
        "today_start": (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat(),
        "yesterday_start": (datetime.now(timezone.utc) - timedelta(hours=48)).isoformat(),
        "yesterday_end": (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat(),
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
    """Iki donemi seviye ve log bazinda karsilastirir."""
    where_clause, params = build_event_filters(
        level, levels, log_name, category, source, event_id, search, error_code, None, None
    )
    and_prefix = " AND " if where_clause else " WHERE "

    query = f"""
        SELECT period, level, log_name, COUNT(*) as count
        FROM (
            SELECT
                CASE
                    WHEN time_created >= NOW() - INTERVAL '24 hours' THEN 'today'
                    WHEN time_created >= NOW() - INTERVAL '48 hours'
                         AND time_created < NOW() - INTERVAL '24 hours' THEN 'yesterday'
                END as period,
                level,
                log_name
            FROM events
            {where_clause}{and_prefix}time_created >= NOW() - INTERVAL '48 hours'
        ) t
        WHERE period IS NOT NULL
        GROUP BY period, level, log_name
        ORDER BY period, count DESC
    """

    with get_db_cursor() as cur:
        cur.execute(query, params)
        rows = cur.fetchall()

        cur.execute(
            f"""
            SELECT
                COUNT(*) FILTER (WHERE time_created >= NOW() - INTERVAL '24 hours') as today,
                COUNT(*) FILTER (
                    WHERE time_created >= NOW() - INTERVAL '48 hours'
                      AND time_created < NOW() - INTERVAL '24 hours'
                ) as yesterday
            FROM events
            {where_clause}
            """,
            params,
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


# --------------------------------------------------------------------------
# WEBSOCKET — gercek zamanli push
# --------------------------------------------------------------------------

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
                row["time_created"] = row["time_created"].isoformat()
                if row.get("inserted_at"):
                    row["inserted_at"] = row["inserted_at"].isoformat()
                await manager.broadcast({"type": "new_event", "data": row})


@app.on_event("startup")
async def startup_event():
    asyncio.create_task(poll_and_broadcast_new_events())
