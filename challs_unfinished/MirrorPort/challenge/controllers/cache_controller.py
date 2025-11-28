"""
Cache controller for the Hōgetsu Teahouse challenge.
Handles cached content serving and sandboxed markdown display.
"""

import os
import re
import hashlib
import markdown
from flask import send_from_directory, request
from models.session import SessionManager
from config.app_config import Config


class CacheController:
    """Controller for cache-related operations."""

    @staticmethod
    def serve_cache(filename: str):
        """Serve cached URL content with strict CSP.
        If the exact filename is missing (e.g., no extension), try to resolve
        to any file with the same base and a known extension.
        """
        cache_dir = Config.CACHE_DIR
        if not os.path.exists(cache_dir):
            os.makedirs(cache_dir)

        try:
            target_path = os.path.join(cache_dir, filename)
            if not os.path.exists(target_path):
                base = filename
                try:
                    for entry in os.listdir(cache_dir):
                        if entry.startswith(base):
                            # Use the first match
                            filename = entry
                            break
                except Exception:
                    pass

            response = send_from_directory(cache_dir, filename)

            # Add strict CSP headers for cached content
            strict_csp_headers = {
                'Content-Security-Policy': (
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
                ),
                'X-Content-Type-Options': 'nosniff',
                'X-Frame-Options': 'DENY',
                'X-XSS-Protection': '1; mode=block',
                'Referrer-Policy': 'no-referrer',
                'Permissions-Policy': (
                    "accelerometer=(), "
                    "ambient-light-sensor=(), "
                    "autoplay=(), "
                    "battery=(), "
                    "camera=(), "
                    "cross-origin-isolated=(), "
                    "display-capture=(), "
                    "document-domain=(), "
                    "encrypted-media=(), "
                    "execution-while-not-rendered=(), "
                    "execution-while-out-of-viewport=(), "
                    "fullscreen=(), "
                    "geolocation=(), "
                    "gyroscope=(), "
                    "keyboard-map=(), "
                    "magnetometer=(), "
                    "microphone=(), "
                    "midi=(), "
                    "navigation-override=(), "
                    "payment=(), "
                    "picture-in-picture=(), "
                    "publickey-credentials-get=(), "
                    "screen-wake-lock=(), "
                    "sync-xhr=(), "
                    "usb=(), "
                    "web-share=(), "
                    "xr-spatial-tracking=()"
                )
            }

            # Apply headers to response
            for header, value in strict_csp_headers.items():
                response.headers[header] = value

            return response

        except FileNotFoundError:
            return "Cache file not found", 404

    @staticmethod
    def replace_urls_with_cache(text: str, listing_id: int) -> str:
        """Replace image URLs in markdown text with cached file references."""
        def replace_image_url(match):
            alt_text, url = match.groups()
            url_hash = hashlib.md5(url.encode()).hexdigest()

            cache_dir = Config.CACHE_DIR
            possible_extensions = Config.CACHE_FILE_EXTENSIONS

            for ext in possible_extensions:
                cache_filename = f"cache_{listing_id}_{url_hash}{ext}"
                cache_filepath = os.path.join(cache_dir, cache_filename)
                if os.path.exists(cache_filepath):
                    return f'![{alt_text}](/cache/{cache_filename})'

            return f'![{alt_text}](/cache/cache_{listing_id}_{url_hash})'

        text = re.sub(r'!\[([^\]]*)\]\(([^)]+)\)', replace_image_url, text)
        return text

    @staticmethod
    def serve_sandboxed_markdown(listing_id: int):
        """Serve markdown content in a sandboxed HTML page."""
        listing = SessionManager.get_listing_by_id(listing_id)
        if not listing:
            return "Listing not found", 404

        if not listing.note:
            return "Note not found", 404

        note = listing.note

        # Get the processed note with cached URLs
        processed_note = CacheController.replace_urls_with_cache(
            note, listing_id)
        html_content = markdown.markdown(processed_note, extensions=['extra'])

        sandboxed_html = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Listing Note - #{listing_id}</title>
    <style>
        body {{
            margin: 0;
            padding: 20px;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #f8f9fa;
            color: #333;
            line-height: 1.6;
        }}
        .note-container {{
            background: white;
            padding: 25px;
            border-radius: 12px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            max-width: 800px;
            margin: 0 auto;
        }}
        .note-header {{
            border-bottom: 2px solid #e9ecef;
            padding-bottom: 15px;
            margin-bottom: 20px;
        }}
        .note-title {{
            font-size: 1.5em;
            color: #495057;
            margin: 0;
        }}
        .note-meta {{
            color: #6c757d;
            font-size: 0.9em;
            margin-top: 5px;
        }}
        .note-content {{
            font-size: 1.1em;
        }}
        .note-content h1, .note-content h2, .note-content h3 {{
            color: #343a40;
            margin-top: 25px;
            margin-bottom: 15px;
        }}
        .note-content p {{
            margin-bottom: 15px;
        }}
        .note-content a {{
            color: #007bff;
            text-decoration: none;
        }}
        .note-content a:hover {{
            text-decoration: underline;
        }}
        .note-content img {{
            max-width: 100%;
            height: auto;
            border-radius: 8px;
            margin: 10px 0;
        }}
        .note-content code {{
            background: #f8f9fa;
            padding: 2px 6px;
            border-radius: 4px;
            font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
            font-size: 0.9em;
        }}
        .note-content pre {{
            background: #f8f9fa;
            padding: 15px;
            border-radius: 8px;
            overflow-x: auto;
            border-left: 4px solid #007bff;
        }}
        .note-content blockquote {{
            border-left: 4px solid #dee2e6;
            padding-left: 20px;
            margin: 20px 0;
            color: #6c757d;
            font-style: italic;
        }}
        .sandbox-warning {{
            background: #fff3cd;
            border: 1px solid #ffeaa7;
            padding: 10px;
            border-radius: 6px;
            margin-bottom: 20px;
            font-size: 0.9em;
            color: #856404;
        }}
    </style>
</head>
<body>
    <div class="note-container">
        <div class="note-header">
            <h1 class="note-title">Listing Note</h1>
            <div class="note-meta">Listing #{listing_id} • {listing.seller_name} • {listing.created_at}</div>
        </div>
        
        <div class="sandbox-warning">
            ⚠️ This content is displayed in a sandboxed environment for security.
        </div>
        
        <div class="note-content">
            {html_content}
        </div>
    </div>
</body>
</html>
"""

        return sandboxed_html, 200, {
            'Content-Type': 'text/html; charset=utf-8',
            'Content-Security-Policy': (
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
            ),
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'SAMEORIGIN'
        }
