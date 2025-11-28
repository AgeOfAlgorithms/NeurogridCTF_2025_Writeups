"""
Main routes for the Hōgetsu Teahouse challenge.
Handles static file serving and React app routing.
"""

import os
from flask import Blueprint, send_from_directory
from controllers.cache_controller import CacheController
from config.app_config import Config

# Create main blueprint
main_bp = Blueprint('main', __name__)

@main_bp.route('/cache/<filename>')
def serve_cache(filename):
    """Serve cached URL content with strict CSP."""
    return CacheController.serve_cache(filename)

@main_bp.route('/uploads/<filename>')
def serve_upload(filename):
    """Serve uploaded product images."""
    upload_folder = Config.UPLOAD_FOLDER
    # Security: ensure filename doesn't contain path traversal
    filename = os.path.basename(filename)
    filepath = os.path.join(upload_folder, filename)
    
    if not os.path.exists(filepath):
        from flask import abort
        abort(404)
    
    return send_from_directory(upload_folder, filename)

@main_bp.route('/sandbox/<int:listing_id>')
def serve_sandboxed_markdown(listing_id):
    """Serve markdown content in a sandboxed HTML page."""
    return CacheController.serve_sandboxed_markdown(listing_id)
