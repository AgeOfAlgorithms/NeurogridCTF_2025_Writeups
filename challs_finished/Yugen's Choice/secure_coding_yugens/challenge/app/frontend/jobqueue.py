import json
import time
import redis
from flask import current_app

def _r():
    return redis.Redis.from_url(current_app.config["REDIS_URL"], decode_responses=True)

def enqueue_job(job_id: str, data_b64: str):
    payload = {
        "id": job_id,
        "data": data_b64,
        "queued_at": time.time(),
    }
    _r().lpush(current_app.config["QUEUE_KEY"], json.dumps(payload))

def get_job_result(job_id: str):
    key = f"job:{job_id}:result"
    raw = _r().get(key)
    return raw  # JSON string or None
