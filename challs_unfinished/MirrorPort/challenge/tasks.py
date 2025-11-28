#!/usr/bin/env python3

import os
import io
import hashlib
import subprocess
import tempfile
import urllib.parse
import logging
from celery import Celery
import redis
from datetime import datetime
import shlex
from config.app_config import Config

# Logging removed for production
logger = logging.getLogger(__name__)

# Celery configuration
celery_app = Celery('tasks', broker='redis://localhost:6379')

# Redis connection
redis_client = redis.Redis(host='localhost', port=6379,
                           db=0, decode_responses=True)


@celery_app.task
def fetch_url(url: str, listing_id, curl_binary='/usr/bin/curl'):
    if url.startswith(('gopher://', 'file://', "-K", "-k")):
        return {
            'url': url,
            'error': 'Skipped URL',
            'success': False,
            'timestamp': datetime.now().isoformat()
        }
    try:
        # Create cache directory if it doesn't exist
        cache_dir = Config.CACHE_DIR
        temp_dir = Config.TEMP_CACHE_DIR
        if not os.path.exists(cache_dir):
            os.makedirs(cache_dir, mode=0o755)
        if not os.path.exists(temp_dir):
            os.makedirs(temp_dir, mode=0o755)

        # Generate cache filename
        url_hash = hashlib.md5(url.encode()).hexdigest()
        temp_file = os.path.join(temp_dir, f"temp_{listing_id}_{url_hash}")

        # Build curl command
        curl_cmd = [
            '-s',  # Silent mode
            '-L',  # Follow redirects
            '-m', '30',  # 30 second timeout
            '-A', 'Ayame-Teahouse-Fetcher/1.0',  # User agent
            '-D', f"{temp_file}.headers",  # Save headers to file
            '-o', temp_file,  # Output to temp file
            '--url', url  # Explicitly specify URL
        ]
        curl_cmd = f"{curl_binary} {shlex.join(curl_cmd)}"

        # Execute curl command
        result = subprocess.run(
            curl_cmd, capture_output=True, shell=True, text=True, timeout=35)

        if result.returncode != 0:
            error_msg = f"curl failed with return code {result.returncode}"
            if result.stderr:
                error_msg += f": {result.stderr}"
            if result.stdout:
                error_msg += f" (stdout: {result.stdout})"
            logger.error(error_msg)
            return {
                'url': url,
                'error': error_msg,
                'success': False,
                'timestamp': datetime.now().isoformat()
            }

        # Check if temp file was created
        if not os.path.exists(temp_file):
            logger.error(f"curl did not create output file: {temp_file}")
            return {
                'url': url,
                'error': f"curl did not create output file: {temp_file}",
                'success': False,
                'timestamp': datetime.now().isoformat()
            }

        # Read the downloaded content
        with open(temp_file, 'rb') as f:
            content_data = f.read()

        # Read headers to get content type
        content_type = None
        response_code = 200  # Default

        try:
            with open(f"{temp_file}.headers", 'r') as f:
                headers = f.read()
                for line in headers.split('\n'):
                    if line.lower().startswith('content-type:'):
                        content_type = line.split(':', 1)[1].strip()
                    elif line.lower().startswith('http/'):
                        # Extract status code from HTTP response line
                        parts = line.split()
                        if len(parts) >= 2:
                            try:
                                response_code = int(parts[1])
                            except ValueError:
                                pass
        except Exception as e:
            pass

        # Determine file extension based on content type
        file_extension = ''
        if content_type:
            if 'image/jpeg' in content_type or 'image/jpg' in content_type:
                file_extension = '.jpg'
            elif 'image/png' in content_type:
                file_extension = '.png'
            elif 'image/gif' in content_type:
                file_extension = '.gif'
            elif 'image/webp' in content_type:
                file_extension = '.webp'
            elif 'image/svg' in content_type:
                file_extension = '.svg'
            elif 'text/html' in content_type:
                file_extension = '.html'
            elif 'text/plain' in content_type:
                file_extension = '.txt'
            elif 'application/json' in content_type:
                file_extension = '.json'
            elif 'application/xml' in content_type or 'text/xml' in content_type:
                file_extension = '.xml'

        # Final cache filename
        cache_filename = f"cache_{listing_id}_{url_hash}{file_extension}"
        cache_filepath = os.path.join(cache_dir, cache_filename)

        # Move temp file to final location
        os.rename(temp_file, cache_filepath)

        # Clean up temp files
        try:
            os.remove(f"{temp_file}.headers")
        except:
            pass

        # Store in Redis for status checking (decode if text)
        try:
            if file_extension in ['.html', '.txt', '.json', '.xml']:
                redis_data = content_data.decode('utf-8', errors='ignore')
            else:
                redis_data = f"Binary content ({len(content_data)} bytes)"
        except:
            redis_data = f"Content ({len(content_data)} bytes)"

        result_key = f"url_result:{listing_id}:{hash(url)}"
        redis_client.setex(result_key, 3600, redis_data)

        return {
            'url': url,
            'status_code': response_code,
            'response_length': len(content_data),
            'cache_file': cache_filename,
            'success': True,
            'timestamp': datetime.now().isoformat()
        }

    except Exception as e:
        error_msg = str(e)

        # Clean up temp files on error
        try:
            temp_file = os.path.join(
                temp_dir, f"temp_{listing_id}_{hashlib.md5(url.encode()).hexdigest()}")
            if os.path.exists(temp_file):
                os.remove(temp_file)
            if os.path.exists(f"{temp_file}.headers"):
                os.remove(f"{temp_file}.headers")
        except:
            pass

        result_key = f"url_error:{listing_id}:{hash(url)}"
        redis_client.setex(result_key, 3600, error_msg)

        return {
            'url': url,
            'error': error_msg,
            'success': False,
            'timestamp': datetime.now().isoformat()
        }


@celery_app.task
def process_markdown_links(content, note_id):
    import re

    url_pattern = r'\[([^\]]+)\]\(([^)]+)\)'
    matches = re.findall(url_pattern, content)

    urls = [url for _, url in matches]

    print(f"[{datetime.now()}] Found {len(urls)} URLs in note {note_id}")

    for url in urls:
        fetch_url.delay(url, note_id)

    return len(urls)


if __name__ == '__main__':
    celery_app.start()
