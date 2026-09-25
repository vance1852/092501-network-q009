"""SQLite 结构、事务和审计事件辅助函数。"""
from __future__ import annotations
import json, sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Iterator

SCHEMA = """
CREATE TABLE IF NOT EXISTS users(user_id TEXT PRIMARY KEY,role TEXT NOT NULL,salt TEXT NOT NULL,password_hash TEXT NOT NULL,active INTEGER NOT NULL DEFAULT 1,created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY,user_id TEXT NOT NULL,expires_at TEXT NOT NULL,active INTEGER NOT NULL DEFAULT 1);
CREATE TABLE IF NOT EXISTS segments(segment_id TEXT PRIMARY KEY,district TEXT NOT NULL,network_type TEXT NOT NULL,length_m REAL NOT NULL,criticality INTEGER NOT NULL,status TEXT NOT NULL,created_at TEXT NOT NULL,updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS readings(reading_id TEXT PRIMARY KEY,segment_id TEXT NOT NULL REFERENCES segments(segment_id),sensor_id TEXT NOT NULL,pressure_kpa REAL NOT NULL,flow_lps REAL NOT NULL,acoustic_db REAL NOT NULL,observed_at TEXT NOT NULL,alert_id TEXT,UNIQUE(segment_id,sensor_id,observed_at));
CREATE TABLE IF NOT EXISTS alerts(alert_id TEXT PRIMARY KEY,segment_id TEXT NOT NULL REFERENCES segments(segment_id),sensor_id TEXT NOT NULL DEFAULT '',anomaly_type TEXT NOT NULL DEFAULT '',fingerprint TEXT NOT NULL UNIQUE,severity TEXT NOT NULL,score REAL NOT NULL,status TEXT NOT NULL,first_seen TEXT,last_seen TEXT,occurrences INTEGER NOT NULL DEFAULT 1,source_ids TEXT NOT NULL DEFAULT '[]',created_at TEXT NOT NULL,resolved_at TEXT);
CREATE TABLE IF NOT EXISTS work_orders(work_order_id TEXT PRIMARY KEY,segment_id TEXT NOT NULL,alert_id TEXT NOT NULL,assignee TEXT NOT NULL,status TEXT NOT NULL,priority INTEGER NOT NULL,created_at TEXT NOT NULL,updated_at TEXT NOT NULL);
CREATE UNIQUE INDEX IF NOT EXISTS work_orders_active_alert ON work_orders(alert_id) WHERE status NOT IN ('completed','cancelled');
CREATE TABLE IF NOT EXISTS resources(resource_id TEXT PRIMARY KEY,kind TEXT NOT NULL,district TEXT NOT NULL,capacity INTEGER NOT NULL,available INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS allocations(allocation_id TEXT PRIMARY KEY,resource_id TEXT NOT NULL,work_order_id TEXT NOT NULL,quantity INTEGER NOT NULL,created_at TEXT NOT NULL,UNIQUE(resource_id,work_order_id));
CREATE TABLE IF NOT EXISTS audit_events(event_id INTEGER PRIMARY KEY AUTOINCREMENT,entity_type TEXT NOT NULL,entity_id TEXT NOT NULL,action TEXT NOT NULL,actor TEXT NOT NULL,payload TEXT NOT NULL,created_at TEXT NOT NULL);
"""
def utcnow() -> str: return datetime.now(timezone.utc).isoformat()
def _columns(db: sqlite3.Connection, table: str) -> set[str]:
    return {row[1] for row in db.execute(f"PRAGMA table_info({table})")}
def _migrate(db: sqlite3.Connection) -> None:
    """为既有数据库补齐告警去重与读数关联所需的新列。"""
    alerts=_columns(db,"alerts")
    for column,ddl in (("sensor_id","ALTER TABLE alerts ADD COLUMN sensor_id TEXT NOT NULL DEFAULT ''"),("anomaly_type","ALTER TABLE alerts ADD COLUMN anomaly_type TEXT NOT NULL DEFAULT ''"),("first_seen","ALTER TABLE alerts ADD COLUMN first_seen TEXT"),("last_seen","ALTER TABLE alerts ADD COLUMN last_seen TEXT"),("occurrences","ALTER TABLE alerts ADD COLUMN occurrences INTEGER NOT NULL DEFAULT 1"),("source_ids","ALTER TABLE alerts ADD COLUMN source_ids TEXT NOT NULL DEFAULT '[]'")):
        if column not in alerts: db.execute(ddl)
    db.execute("UPDATE alerts SET first_seen=created_at WHERE first_seen IS NULL"); db.execute("UPDATE alerts SET last_seen=created_at WHERE last_seen IS NULL")
    if "alert_id" not in _columns(db,"readings"): db.execute("ALTER TABLE readings ADD COLUMN alert_id TEXT")
def connect(path: str = ":memory:") -> sqlite3.Connection:
    db=sqlite3.connect(path,timeout=10,check_same_thread=False); db.row_factory=sqlite3.Row; db.execute("PRAGMA foreign_keys=ON"); db.execute("PRAGMA journal_mode=WAL"); db.executescript(SCHEMA); _migrate(db); db.execute("CREATE INDEX IF NOT EXISTS alerts_dedup_lookup ON alerts(segment_id,sensor_id,anomaly_type,status)"); db.commit(); return db
@contextmanager
def transaction(db: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    try: db.execute("BEGIN IMMEDIATE"); yield db; db.commit()
    except Exception: db.rollback(); raise
def audit(db, entity_type, entity_id, action, actor, payload):
    db.execute("INSERT INTO audit_events(entity_type,entity_id,action,actor,payload,created_at) VALUES(?,?,?,?,?,?)",(entity_type,entity_id,action,actor,json.dumps(payload,ensure_ascii=False,sort_keys=True),utcnow()))
def rows(db, query, args=()): return [dict(r) for r in db.execute(query,args).fetchall()]
