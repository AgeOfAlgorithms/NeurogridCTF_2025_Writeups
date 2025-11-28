"""
Session management model for the Ninja Scroll Marketplace challenge.
Handles global listing storage using Redis.
"""

from typing import List, Optional
import json
import redis
from models.listing import Listing

# Global Redis connection for listings storage
_redis_client = None

def get_redis_client():
    """Get Redis client for global listings storage."""
    global _redis_client
    if _redis_client is None:
        _redis_client = redis.Redis(host='localhost', port=6379, db=0, decode_responses=True)
    return _redis_client


class SessionManager:
    """Manages global listing storage."""
    
    LISTINGS_KEY = 'marketplace:listings'
    LISTING_COUNTER_KEY = 'marketplace:listing_counter'
    
    @staticmethod
    def _deserialize_listing(listing_dict: dict) -> Listing:
        """Convert dict to Listing object."""
        return Listing(
            id=listing_dict['id'],
            seller_name=listing_dict['seller_name'],
            scroll_name=listing_dict['scroll_name'],
            price=listing_dict['price'],
            description=listing_dict['description'],
            note=listing_dict.get('note', ''),
            urls=listing_dict.get('urls', []),
            image_url=listing_dict.get('image_url'),
            is_processed=listing_dict.get('is_processed', False),
            created_at=listing_dict.get('created_at'),
            updated_at=listing_dict.get('updated_at')
        )
    
    @staticmethod
    def get_all_listings() -> List[Listing]:
        """Get all listings from the marketplace."""
        try:
            redis_client = get_redis_client()
            listings_data = redis_client.lrange(SessionManager.LISTINGS_KEY, 0, -1)
            
            listings = []
            for listing_json in listings_data:
                listing_dict = json.loads(listing_json)
                listings.append(SessionManager._deserialize_listing(listing_dict))
            
            # Sort by ID (newest first)
            listings.sort(key=lambda x: x.id, reverse=True)
            return listings
        except Exception:
            # Fallback to empty list if Redis fails
            return []
    
    @staticmethod
    def get_user_listings(seller_name: str) -> List[Listing]:
        """Get listings for a specific seller."""
        all_listings = SessionManager.get_all_listings()
        return [listing for listing in all_listings if listing.seller_name == seller_name]
    
    @staticmethod
    def add_listing(listing: Listing) -> None:
        """Add listing to global marketplace."""
        try:
            redis_client = get_redis_client()
            listing_json = json.dumps(listing.to_dict())
            redis_client.lpush(SessionManager.LISTINGS_KEY, listing_json)
            # Keep only last 1000 listings to prevent memory issues
            redis_client.ltrim(SessionManager.LISTINGS_KEY, 0, 999)
        except Exception:
            # Silently fail if Redis is unavailable
            pass
    
    @staticmethod
    def get_next_listing_id() -> int:
        """Get next available listing ID."""
        try:
            redis_client = get_redis_client()
            return redis_client.incr(SessionManager.LISTING_COUNTER_KEY)
        except Exception:
            # Fallback: count existing listings
            all_listings = SessionManager.get_all_listings()
            return len(all_listings) + 1 if all_listings else 1
    
    @staticmethod
    def delete_listing(listing_id: int, seller_name: str) -> Optional[Listing]:
        """Delete a listing (only by its seller)."""
        try:
            redis_client = get_redis_client()
            listings_data = redis_client.lrange(SessionManager.LISTINGS_KEY, 0, -1)
            
            deleted_listing = None
            updated_listings = []
            
            for listing_json in listings_data:
                listing_dict = json.loads(listing_json)
                listing = SessionManager._deserialize_listing(listing_dict)
                
                if listing.id == listing_id and listing.seller_name == seller_name:
                    deleted_listing = listing
                else:
                    updated_listings.append(listing_json)
            
            if deleted_listing:
                # Rebuild the list in Redis
                redis_client.delete(SessionManager.LISTINGS_KEY)
                if updated_listings:
                    redis_client.lpush(SessionManager.LISTINGS_KEY, *updated_listings)
            
            return deleted_listing
        except Exception:
            return None
    
    @staticmethod
    def update_listing(updated: Listing) -> bool:
        """Persist an updated listing back to Redis list by replacing the matching id."""
        try:
            redis_client = get_redis_client()
            listings_data = redis_client.lrange(SessionManager.LISTINGS_KEY, 0, -1)
            modified = False
            new_list = []
            for listing_json in listings_data:
                listing_dict = json.loads(listing_json)
                if listing_dict.get('id') == updated.id:
                    new_list.append(json.dumps(updated.to_dict()))
                    modified = True
                else:
                    new_list.append(listing_json)
            if modified:
                redis_client.delete(SessionManager.LISTINGS_KEY)
                if new_list:
                    redis_client.lpush(SessionManager.LISTINGS_KEY, *new_list)
            return modified
        except Exception:
            return False
    
    @staticmethod
    def get_listing_by_id(listing_id: int) -> Optional[Listing]:
        """Get listing by ID from global marketplace."""
        all_listings = SessionManager.get_all_listings()
        for listing in all_listings:
            if listing.id == listing_id:
                return listing
        return None
