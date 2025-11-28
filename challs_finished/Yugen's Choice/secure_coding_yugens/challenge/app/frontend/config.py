import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-insecure")
    DATABASE = os.getenv("DATABASE", "./frontend.db")
    REDIS_URL = os.getenv("REDIS_URL", "unix:///tmp/redis.sock?db=0")
    UPLOAD_FOLDER = os.getenv("UPLOAD_FOLDER", "./uploads")
    MAX_CONTENT_LENGTH = int(os.getenv("MAX_CONTENT_LENGTH", str(1 * 1024 * 1024)))
    QUEUE_KEY = os.getenv("QUEUE_KEY", "print:queue")

    @staticmethod
    def ensure_dirs():
        os.makedirs(Config.UPLOAD_FOLDER, exist_ok=True)
        os.makedirs(os.path.dirname(Config.DATABASE) or ".", exist_ok=True)
