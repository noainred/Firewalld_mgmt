"""
SQLite 기반 데이터 저장소.
- proxy_rules : 프록시(포트포워딩) 규칙
- servers     : A/B 서버 인벤토리
- audit_log   : 누가 언제 무엇을 했는지 감사 로그
"""
import os
import sqlite3
from datetime import datetime

from config import Config

SCHEMA = """
CREATE TABLE IF NOT EXISTS proxy_rules (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL,
    protocol    TEXT NOT NULL DEFAULT 'tcp',
    listen_port INTEGER NOT NULL,
    dest_addr   TEXT NOT NULL,
    dest_port   INTEGER NOT NULL,
    source_addr TEXT,
    description TEXT,
    enabled     INTEGER NOT NULL DEFAULT 1,
    created_by  TEXT,
    created_at  TEXT,
    updated_at  TEXT
);

CREATE TABLE IF NOT EXISTS servers (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL,
    role        TEXT NOT NULL DEFAULT 'client',  -- client(A) / target(B) / proxy
    address     TEXT NOT NULL,
    description TEXT,
    created_at  TEXT
);

CREATE TABLE IF NOT EXISTS audit_log (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts        TEXT,
    actor     TEXT,
    action    TEXT,
    target    TEXT,
    detail    TEXT,
    result    TEXT
);
"""


def _now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def get_db():
    os.makedirs(os.path.dirname(Config.DB_PATH), exist_ok=True)
    conn = sqlite3.connect(Config.DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.executescript(SCHEMA)
    conn.commit()
    conn.close()


# ----- proxy_rules -----
def list_rules():
    conn = get_db()
    rows = conn.execute("SELECT * FROM proxy_rules ORDER BY id").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_rule(rule_id):
    conn = get_db()
    row = conn.execute(
        "SELECT * FROM proxy_rules WHERE id=?", (rule_id,)
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def create_rule(data, actor):
    conn = get_db()
    cur = conn.execute(
        """INSERT INTO proxy_rules
           (name, protocol, listen_port, dest_addr, dest_port,
            source_addr, description, enabled, created_by, created_at, updated_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
        (data["name"], data["protocol"], data["listen_port"],
         data["dest_addr"], data["dest_port"], data.get("source_addr") or None,
         data.get("description"), int(data.get("enabled", 1)),
         actor, _now(), _now()),
    )
    conn.commit()
    rule_id = cur.lastrowid
    conn.close()
    return rule_id


def update_rule(rule_id, data):
    conn = get_db()
    conn.execute(
        """UPDATE proxy_rules SET
           name=?, protocol=?, listen_port=?, dest_addr=?, dest_port=?,
           source_addr=?, description=?, enabled=?, updated_at=?
           WHERE id=?""",
        (data["name"], data["protocol"], data["listen_port"],
         data["dest_addr"], data["dest_port"], data.get("source_addr") or None,
         data.get("description"), int(data.get("enabled", 1)),
         _now(), rule_id),
    )
    conn.commit()
    conn.close()


def delete_rule(rule_id):
    conn = get_db()
    conn.execute("DELETE FROM proxy_rules WHERE id=?", (rule_id,))
    conn.commit()
    conn.close()


# ----- servers -----
def list_servers():
    conn = get_db()
    rows = conn.execute("SELECT * FROM servers ORDER BY role, id").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def create_server(data):
    conn = get_db()
    conn.execute(
        """INSERT INTO servers (name, role, address, description, created_at)
           VALUES (?,?,?,?,?)""",
        (data["name"], data["role"], data["address"],
         data.get("description"), _now()),
    )
    conn.commit()
    conn.close()


def delete_server(server_id):
    conn = get_db()
    conn.execute("DELETE FROM servers WHERE id=?", (server_id,))
    conn.commit()
    conn.close()


# ----- audit_log -----
def add_audit(actor, action, target, detail, result):
    conn = get_db()
    conn.execute(
        """INSERT INTO audit_log (ts, actor, action, target, detail, result)
           VALUES (?,?,?,?,?,?)""",
        (_now(), actor, action, target, detail, result),
    )
    conn.commit()
    conn.close()


def list_audit(limit=200):
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]
