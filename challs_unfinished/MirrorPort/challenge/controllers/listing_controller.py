"""
Listing controller for the Ninja Scroll Marketplace challenge.
Handles listing creation, retrieval, and management.
"""

import os
import hashlib
from werkzeug.utils import secure_filename
from flask import request, jsonify
from models.listing import Listing
from models.session import SessionManager
from tasks import fetch_url
from config.app_config import Config
from controllers.cache_controller import CacheController


class ListingController:
    """Controller for listing-related operations."""
    
    @staticmethod
    def get_all_listings():
        """Get all listings from the marketplace."""
        all_listings = SessionManager.get_all_listings()
        return jsonify({'listings': [listing.to_dict() for listing in all_listings]})
    
    @staticmethod
    def get_my_listings():
        """Get listings for the current user."""
        # For GET requests, use query params; for POST requests, use JSON body
        if request.method == 'GET':
            seller_name = request.args.get('seller_name', '').strip()
        else:
            data = request.get_json() or {}
            seller_name = data.get('seller_name', '').strip()
        
        if not seller_name:
            return jsonify({'error': 'Seller name is required'}), 400
        
        user_listings = SessionManager.get_user_listings(seller_name)
        return jsonify({'listings': [listing.to_dict() for listing in user_listings]})
    
    @staticmethod
    def create_listing():
        """Create a new scroll listing."""
        data = request.get_json()
        
        seller_name = data.get('seller_name', '').strip()
        scroll_name = data.get('scroll_name', '').strip()
        price = data.get('price')
        description = data.get('description', '').strip()
        note = data.get('note', '').strip()
        image_url = data.get('image_url', '').strip()
        
        if not seller_name or not scroll_name or price is None:
            return jsonify({'error': 'Seller name, scroll name, and price are required'}), 400
        
        try:
            price = float(price)
            if price < 0:
                return jsonify({'error': 'Price must be non-negative'}), 400
        except (ValueError, TypeError):
            return jsonify({'error': 'Invalid price'}), 400
        
        # Extract URLs from markdown note
        urls = Listing.extract_urls_from_markdown(note) if note else []
        # Filter out non-HTTP URLs for security
        urls = Listing.filter_http_urls(urls)
        
        # Create new listing with global ID
        listing_id = SessionManager.get_next_listing_id()
        listing = Listing(
            id=listing_id,
            seller_name=seller_name,
            scroll_name=scroll_name,
            price=price,
            description=description,
            note=note,
            urls=urls,
            image_url=image_url if image_url else None,
            is_processed=False
        )
        
        SessionManager.add_listing(listing)
        
        # Trigger URL fetching for any URLs in the note
        for url in urls:
            fetch_url.delay(url, listing.id)
        
        return jsonify({
            'success': True,
            'listing_id': listing.id
        })
    
    @staticmethod
    def get_listing(listing_id: int):
        """Get a single listing by ID."""
        listing = SessionManager.get_listing_by_id(listing_id)
        if not listing:
            return jsonify({'error': 'Listing not found'}), 404
        return jsonify({'listing': listing.to_dict()})
    
    @staticmethod
    def delete_listing(listing_id: int):
        """Delete a listing (only if user is the seller)."""
        # For GET requests, use query params; for DELETE requests, prefer query params but also check JSON
        seller_name = request.args.get('seller_name', '').strip()
        if not seller_name and request.is_json:
            data = request.get_json() or {}
            seller_name = data.get('seller_name', '').strip()
        
        if not seller_name:
            return jsonify({'error': 'Seller name is required'}), 400
        
        deleted_listing = SessionManager.delete_listing(listing_id, seller_name)
        if deleted_listing:
            return jsonify({'success': True})
        else:
            return jsonify({'error': 'Listing not found or you are not the seller'}), 404
    
    @staticmethod
    def get_listing_status(listing_id: int):
        """Check if a listing has been processed."""
        import os
        import hashlib
        
        listing = SessionManager.get_listing_by_id(listing_id)
        if not listing:
            return jsonify({'error': 'Listing not found'}), 404
        
        # If no URLs, listing is immediately completed (persist state)
        if not listing.urls:
            if not listing.is_processed:
                listing.is_processed = True
                try:
                    SessionManager.update_listing(listing)
                except Exception:
                    pass
            return jsonify({'processed': True})
        
        # Check if all URLs have been processed
        processed = True
        cache_dir = Config.CACHE_DIR
        
        for url in listing.urls:
            url_hash = hashlib.md5(url.encode()).hexdigest()
            
            # Check if any cached file exists for this URL (with any extension)
            possible_extensions = Config.CACHE_FILE_EXTENSIONS
            file_exists = False
            
            for ext in possible_extensions:
                cache_filename = f"cache_{listing_id}_{url_hash}{ext}"
                cache_filepath = os.path.join(cache_dir, cache_filename)
                if os.path.exists(cache_filepath):
                    file_exists = True
                    break
            
            if not file_exists:
                # Fallback: check for any cache file starting with the base (handles extensionless files)
                base = f"cache_{listing_id}_{url_hash}"
                try:
                    for entry in os.listdir(cache_dir):
                        if entry.startswith(base):
                            file_exists = True
                            break
                except Exception:
                    pass
            if not file_exists:
                processed = False
                break
        
        # Update listing status only if all URLs are processed, and persist it
        if processed and not listing.is_processed:
            listing.is_processed = True
            try:
                SessionManager.update_listing(listing)
            except Exception:
                pass
        
        return jsonify({'processed': bool(listing.is_processed)})
    
    @staticmethod
    def upload_image():
        """Handle image upload for product images."""
        if 'image' not in request.files:
            return jsonify({'error': 'No image file provided'}), 400
        
        file = request.files['image']
        
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        # Check file extension
        filename = secure_filename(file.filename)
        if '.' not in filename:
            return jsonify({'error': 'File must have an extension'}), 400
        
        extension = filename.rsplit('.', 1)[1].lower()
        if extension not in Config.ALLOWED_EXTENSIONS:
            return jsonify({'error': f'File type not allowed. Allowed: {", ".join(Config.ALLOWED_EXTENSIONS)}'}), 400
        
        # Check file size
        file.seek(0, os.SEEK_END)
        file_size = file.tell()
        file.seek(0)
        
        if file_size > Config.MAX_UPLOAD_SIZE:
            return jsonify({'error': f'File too large. Max size: {Config.MAX_UPLOAD_SIZE / 1024 / 1024}MB'}), 400
        
        # Create upload directory if it doesn't exist
        upload_dir = Config.UPLOAD_FOLDER
        if not os.path.exists(upload_dir):
            os.makedirs(upload_dir, mode=0o755)
        
        # Generate unique filename
        file_hash = hashlib.md5(file.read()).hexdigest()
        file.seek(0)  # Reset file pointer
        unique_filename = f"{file_hash}.{extension}"
        filepath = os.path.join(upload_dir, unique_filename)
        
        # Save file if it doesn't already exist
        if not os.path.exists(filepath):
            file.save(filepath)
            os.chmod(filepath, 0o644)
        
        # Return URL for the uploaded image
        image_url = f"/uploads/{unique_filename}"
        return jsonify({
            'success': True,
            'image_url': image_url,
            'filename': unique_filename
        })
    
    @staticmethod
    def get_processed_note(listing_id: int):
        """Get listing note with cached URLs replaced."""
        listing = SessionManager.get_listing_by_id(listing_id)
        if not listing:
            return jsonify({'error': 'Listing not found'}), 404
        
        if not listing.note:
            return jsonify({'processed_note': ''})
        
        # Replace URLs with cached versions
        processed_note = CacheController.replace_urls_with_cache(listing.note, listing_id)
        return jsonify({'processed_note': processed_note})

