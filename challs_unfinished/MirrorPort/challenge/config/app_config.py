"""
Application configuration for the Hōgetsu Teahouse challenge.
Centralizes all configuration settings.
"""

import os
import string
import random


class Config:
    """Base configuration class."""
    
    # Flask configuration
    SECRET_KEY = ''.join(random.choices(string.ascii_letters + string.digits, k=32))
    SESSION_TYPE = 'filesystem'
    SESSION_PERMANENT = False
    SESSION_USE_SIGNER = True
    SESSION_KEY_PREFIX = 'ayame:'
    
    # Static files
    STATIC_FOLDER = '/app/ui/dist/client'
    STATIC_URL_PATH = ''
    
    # Redis configuration
    REDIS_HOST = 'localhost'
    REDIS_PORT = 6379
    REDIS_DB = 0
    REDIS_DECODE_RESPONSES = True
    
    # Celery configuration
    CELERY_BROKER_URL = 'redis://localhost:6379'
    
    # Cache configuration
    CACHE_DIR = '/app/cache'
    TEMP_CACHE_DIR = '/tmp/cache'
    CACHE_FILE_EXTENSIONS = ['.jpg', '.png', '.gif', '.webp', '.svg', '.html', '.txt', '.json', '.xml']
    
    # Upload configuration
    UPLOAD_FOLDER = '/app/uploads'
    MAX_UPLOAD_SIZE = 5 * 1024 * 1024  # 5MB
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
    
    # Security headers
    SECURITY_HEADERS = {
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'X-XSS-Protection': '1; mode=block',
        'Referrer-Policy': 'no-referrer'
    }
    
    # CSP for cached content
    STRICT_CSP = (
        "default-src 'none'; "
        "script-src 'none'; "
        "object-src 'none'; "
        "base-uri 'none'; "
        "form-action 'none'; "
        "frame-ancestors 'none'; "
        "connect-src 'none'; "
        "img-src 'self' data:; "
        "style-src 'self' 'unsafe-inline'; "
        "font-src 'self'; "
        "media-src 'none'; "
        "manifest-src 'none'; "
        "worker-src 'none'; "
        "child-src 'none'; "
        "frame-src 'none'; "
        "report-uri /csp-report"
    )
    
    # CSP for sandboxed content
    SANDBOX_CSP = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "font-src 'self'; "
        "connect-src 'self'; "
        "frame-src 'self'; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "form-action 'self'"
    )
