#!/usr/bin/env python3
import os, json, time, random, threading, math
from datetime import datetime, timedelta, timezone

from flask import Flask, jsonify
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy import func

from dotenv import load_dotenv
load_dotenv()

# ── Config ───────────────────────────────────────────────────────────────────
LT_DB_URL       = os.environ.get("LT_DB_URL", "postgresql+psycopg2://postgres:postgres@127.0.0.1:5432/shugo_system_db")
LT_ROWS         = int(os.environ.get("LT_ROWS", "8"))
LT_COLS         = int(os.environ.get("LT_COLS", "28"))
LT_BUS_COUNT    = int(os.environ.get("LT_BUS_COUNT", "7"))
LT_TICK_SEC     = int(os.environ.get("LT_TICK_SEC", "10"))
LT_ONE_BASED    = os.environ.get("LT_ONE_BASED", "false").lower() in ("1","true","yes")

LT_COL_LEFT_LIMIT  = int(os.environ.get("LT_COL_LEFT_LIMIT", "0"))
LT_COL_RIGHT_LIMIT = int(os.environ.get("LT_COL_RIGHT_LIMIT", str(max(0, LT_COLS - 1))))
LT_COL_RIGHT_LIMIT = max(0, min(LT_COLS - 1, LT_COL_RIGHT_LIMIT))
LT_COL_LEFT_LIMIT  = max(0, min(LT_COL_LEFT_LIMIT, LT_COL_RIGHT_LIMIT))

SPEED_MIN_NODES = float(os.environ.get("LT_SPEED_MIN_NODES", "0.6"))
SPEED_MAX_NODES = float(os.environ.get("LT_SPEED_MAX_NODES", "1.6"))
DWELL_MIN_SEC   = int(os.environ.get("LT_DWELL_MIN_SEC", "8"))
DWELL_MAX_SEC   = int(os.environ.get("LT_DWELL_MAX_SEC", "35"))
REVERSE_CHANCE  = float(os.environ.get("LT_REVERSE_CHANCE", "0.25"))

# ── App / DB ─────────────────────────────────────────────────────────────────
app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = LT_DB_URL
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

# ── Models ───────────────────────────────────────────────────────────────────
class Bus(db.Model):
    __tablename__ = "logic_buses"
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(32), unique=True, nullable=False)
    start_id   = db.Column(db.Integer, nullable=False)
    end_id     = db.Column(db.Integer, nullable=False)
    path_ids   = db.Column(JSONB, nullable=False, default=list)
    cur_index  = db.Column(db.Float, nullable=False, default=0.0)
    speed      = db.Column(db.Float, nullable=False, default=1.0)
    paused_until = db.Column(db.DateTime(timezone=True), nullable=True)
    created_at = db.Column(db.DateTime(timezone=True), server_default=func.now())
    updated_at = db.Column(db.DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

class BusPoint(db.Model):
    __tablename__ = "logic_bus_points"
    id = db.Column(db.BigInteger, primary_key=True)
    bus_id  = db.Column(db.Integer, db.ForeignKey("logic_buses.id", ondelete="CASCADE"), nullable=False, index=True)
    at      = db.Column(db.DateTime(timezone=True), nullable=False, index=True, default=lambda: datetime.now(timezone.utc))
    node_id = db.Column(db.Integer, nullable=False)
    meta    = db.Column(JSONB, nullable=False, default=dict)

# ── Grid / Pathfinding ───────────────────────────────────────────────────────
def node_id(row, col):
    return row * LT_COLS + col

def neighbors(nid):
    r, c = divmod(nid, LT_COLS)
    for dc in (-1, 1):
        nc = c + dc
        if 0 <= nc < LT_COLS:
            yield node_id(r, nc)
    for dr in (-1, 1):
        nr = r + dr
        if 0 <= nr < LT_ROWS:
            yield node_id(nr, c)

def bfs_path(s, g):
    if s == g:
        return [s]
    N = LT_ROWS * LT_COLS
    prev = [-1] * N
    seen = [False] * N
    q = [s]
    seen[s] = True
    while q:
        u = q.pop(0)
        if u == g:
            break
        for v in neighbors(u):
            if not seen[v]:
                seen[v] = True
                prev[v] = u
                q.append(v)
    if not seen[g]:
        return []
    path = []
    cur = g
    while cur != -1:
        path.append(cur)
        if cur == s:
            break
        cur = prev[cur]
    path.reverse()
    return path

def random_left_edge_node():
    return node_id(random.randrange(0, LT_ROWS), LT_COL_LEFT_LIMIT)

def random_right_edge_node():
    return node_id(random.randrange(0, LT_ROWS), LT_COL_RIGHT_LIMIT)

def col_of(nid):
    return nid % LT_COLS

def clamp_end_to_window(nid):
    r, c = divmod(nid, LT_COLS)
    c = max(LT_COL_LEFT_LIMIT, min(LT_COL_RIGHT_LIMIT, c))
    return node_id(r, c)

def pick_new_route(prev_end=None):
    if prev_end is not None:
        prev_end = clamp_end_to_window(prev_end)
    if prev_end is not None and col_of(prev_end) == LT_COL_RIGHT_LIMIT and random.random() < REVERSE_CHANCE:
        s, e = random_right_edge_node(), random_left_edge_node()
    else:
        s, e = random_left_edge_node(), random_right_edge_node()
    if s == e:
        e = random_right_edge_node()
    path = bfs_path(s, e)
    if not path:
        r = s // LT_COLS
        s = node_id(r, LT_COL_LEFT_LIMIT)
        e = node_id(r, LT_COL_RIGHT_LIMIT)
        path = bfs_path(s, e)
    return s, e, path

# ── Seeding ──────────────────────────────────────────────────────────────────
def seed_buses_if_empty():
    if Bus.query.count() > 0:
        return
    for i in range(LT_BUS_COUNT):
        s, e, path = pick_new_route()
        cur_idx = random.randint(0, max(0, len(path) - 1))
        speed = random.uniform(SPEED_MIN_NODES, SPEED_MAX_NODES)
        b = Bus(
            code=str(i),
            start_id=s, end_id=e, path_ids=path,
            cur_index=float(cur_idx),
            speed=speed,
            paused_until=None,
        )
        db.session.add(b)
    db.session.commit()
    for b in Bus.query.all():
        save_point(b, math.floor(b.cur_index))

# ── State advance ────────────────────────────────────────────────────────────
def save_point(bus: Bus, node_id_int: int):
    db.session.add(BusPoint(
        bus_id=bus.id,
        node_id=node_id_int,
        meta={"speed": bus.speed, "start_id": bus.start_id, "end_id": bus.end_id},
    ))

def step_bus(bus: Bus, now: datetime):
    if bus.paused_until and now < bus.paused_until:
        return False
    path = bus.path_ids or []
    if not path:
        s, e, path = pick_new_route()
        bus.start_id, bus.end_id, bus.path_ids = s, e, path
        bus.cur_index = 0.0
    bus.cur_index += bus.speed
    last_index = max(0, len(path) - 1)
    if bus.cur_index >= last_index:
        bus.cur_index = float(last_index)
        dwell = random.randint(DWELL_MIN_SEC, DWELL_MAX_SEC)
        bus.paused_until = datetime.now(timezone.utc) + timedelta(seconds=dwell)
        if random.random() < REVERSE_CHANCE:
            bus.path_ids = list(reversed(path))
            bus.start_id, bus.end_id = bus.end_id, bus.start_id
            bus.cur_index = 0.0
        else:
            s, e, path2 = pick_new_route(prev_end=bus.end_id)
            bus.start_id, bus.end_id, bus.path_ids = s, e, path2
            bus.cur_index = 0.0
        bus.speed = random.uniform(SPEED_MIN_NODES, SPEED_MAX_NODES)
    node_idx = int(max(0, min(len(bus.path_ids) - 1, round(bus.cur_index))))
    node_id_now = bus.path_ids[node_idx] if bus.path_ids else bus.start_id
    save_point(bus, node_id_now)
    return True

def tick_once():
    now = datetime.now(timezone.utc)
    moved = 0
    for bus in Bus.query.order_by(Bus.id).all():
        if step_bus(bus, now):
            moved += 1
    db.session.commit()
    return moved

# ── Background scheduler ─────────────────────────────────────────────────────
class Ticker(threading.Thread):
    def __init__(self, period_sec: int):
        super().__init__(daemon=True)
        self.period = period_sec
        self._stop = threading.Event()

    def run(self):
        with app.app_context():
            while not self._stop.is_set():
                try:
                    tick_once()
                except Exception as e:
                    print(f"[logic] tick error: {e}", flush=True)
                    db.session.rollback()
                finally:
                    db.session.remove()
                self._stop.wait(self.period)

    def stop(self):
        self._stop.set()

ticker = None

# ── API ─────────────────────────────────────────────────────────────────────
def export_id(nid: int) -> int:
    if nid is None:
        return None
    return (nid + 1) if LT_ONE_BASED else nid

@app.get("/logic/tracker")
def logic_tracker_matrix():
    """Return [starts, currents, ends] for the poller."""
    buses = Bus.query.order_by(Bus.code).all()
    starts, currents, ends = [], [], []
    for b in buses:
        if b.path_ids:
            idx = int(max(0, min(len(b.path_ids) - 1, round(b.cur_index))))
            cur_node = b.path_ids[idx]
        else:
            cur_node = b.start_id
        starts.append(export_id(b.start_id))
        currents.append(export_id(cur_node))
        ends.append(export_id(b.end_id))
    return jsonify([starts, currents, ends])

@app.get("/logic/buses")
def logic_buses_full():
    """Detailed bus state."""
    out = []
    for b in Bus.query.order_by(Bus.code).all():
        if b.path_ids:
            idx = int(max(0, min(len(b.path_ids) - 1, round(b.cur_index))))
            cur_node = b.path_ids[idx]
        else:
            cur_node = b.start_id
        out.append({
            "code": b.code,
            "start_id": export_id(b.start_id),
            "current_id": export_id(cur_node),
            "end_id": export_id(b.end_id),
            "speed_nodes_per_tick": b.speed,
            "paused_until": b.paused_until.isoformat() if b.paused_until else None,
            "path_len": len(b.path_ids or []),
        })
    return jsonify({"one_based": LT_ONE_BASED, "rows": LT_ROWS, "cols": LT_COLS, "buses": out})

# ── Boot ─────────────────────────────────────────────────────────────────────
def boot():
    global ticker
    with app.app_context():
        db.create_all()
        seed_buses_if_empty()
    ticker = Ticker(LT_TICK_SEC)
    ticker.start()

if __name__ == "__main__":
    boot()
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")))
