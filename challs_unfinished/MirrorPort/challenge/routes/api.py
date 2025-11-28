"""
API routes for the Ninja Scroll Marketplace challenge.
Handles all API endpoints for the React frontend.
"""

from flask import Blueprint
from controllers.listing_controller import ListingController

# Create API blueprint
api_bp = Blueprint('api', __name__, url_prefix='/api')

# Listing routes (selling scrolls)
# Note: More specific routes must come before generic ones
@api_bp.route('/listings/my', methods=['GET', 'POST'])
def get_my_listings():
    """Get listings for the current user."""
    return ListingController.get_my_listings()

@api_bp.route('/listings', methods=['GET'])
def get_listings():
    """Get all listings from the marketplace."""
    return ListingController.get_all_listings()

@api_bp.route('/listings', methods=['POST'])
def create_listing():
    """Create a new scroll listing."""
    return ListingController.create_listing()

@api_bp.route('/listings/<int:listing_id>', methods=['GET', 'DELETE'])
def listing_detail(listing_id):
    """Get or delete a listing by ID."""
    from flask import request
    if request.method == 'GET':
        return ListingController.get_listing(listing_id)
    else:
        return ListingController.delete_listing(listing_id)

@api_bp.route('/listings/<int:listing_id>/status', methods=['GET'])
def get_listing_status(listing_id):
    """Check if a listing has been processed."""
    return ListingController.get_listing_status(listing_id)

@api_bp.route('/upload/image', methods=['POST'])
def upload_image():
    """Upload a product image."""
    return ListingController.upload_image()

@api_bp.route('/listings/<int:listing_id>/processed-note', methods=['GET'])
def get_processed_note(listing_id):
    """Get listing note with cached URLs replaced."""
    return ListingController.get_processed_note(listing_id)


