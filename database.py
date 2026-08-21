
import psycopg2
from psycopg2 import pool
from psycopg2.extras import RealDictCursor
from contextlib import contextmanager

DB_CONFIG = {
    "host": "localhost",
    "port": 5432,
    "dbname": "event_monitor",
    "user": "event_admin",
    "password": "change_this_password",   # collector.py ve docker-compose.yml ile ayni olmali
}

# minconn / maxconn: dashboard + collector ayni anda calisirken yeterli olacak sekilde ayarlandi
connection_pool = psycopg2.pool.ThreadedConnectionPool(
    minconn=1,
    maxconn=10,
    **DB_CONFIG,
)


@contextmanager
def get_db_cursor():
    """
    Kullanim:
        with get_db_cursor() as cur:
            cur.execute("SELECT ...")
            rows = cur.fetchall()
    Baglanti otomatik havuza geri verilir.
    """
    conn = connection_pool.getconn()
    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        yield cur
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        cur.close()
        connection_pool.putconn(conn)
