"""
Listing model for the Ninja Scroll Marketplace challenge.
Represents scroll listings posted by sellers.
"""

from datetime import datetime
from typing import List, Dict, Optional
import re


class Listing:
    """Represents a scroll listing posted by a seller."""
    
    def __init__(self, id: int, seller_name: str, scroll_name: str, price: float, 
                 description: str, note: str = '', urls: List[str] = None, 
                 image_url: str = None, is_processed: bool = False, 
                 created_at: str = None, updated_at: str = None):
        self.id = id
        self.seller_name = seller_name
        self.scroll_name = scroll_name
        self.price = price
        self.description = description
        self.note = note
        self.urls = urls or []
        self.image_url = image_url
        self.is_processed = is_processed
        self.created_at = created_at or datetime.now().isoformat()
        self.updated_at = updated_at or datetime.now().isoformat()
    
    def to_dict(self) -> Dict:
        """Convert listing to dictionary for JSON serialization."""
        return {
            'id': self.id,
            'seller_name': self.seller_name,
            'scroll_name': self.scroll_name,
            'price': self.price,
            'description': self.description,
            'note': self.note,
            'urls': self.urls,
            'image_url': self.image_url,
            'is_processed': self.is_processed,
            'created_at': self.created_at,
            'updated_at': self.updated_at
        }
    
    @staticmethod
    def extract_urls_from_markdown(text: str) -> List[str]:
        """Extract image URLs from markdown text."""
        if not text:
            return []
            
        image_pattern = r'!\[([^\]]*)\]\(([^)]+)\)'
        matches = re.findall(image_pattern, text)
        urls = []
        
        for _, url in matches:
            if url.strip():  # Only add non-empty URLs
                urls.append(url.strip())
        
        # Remove duplicates while preserving order
        seen = set()
        unique_urls = []
        for url in urls:
            if url not in seen:
                seen.add(url)
                unique_urls.append(url)
        return unique_urls
    
    @staticmethod
    def filter_http_urls(urls: List[str]) -> List[str]:
        """Filter out non-HTTP URLs for security."""
        import string
        filtered_urls = []
        
        for url in urls[:]:
            if url.strip(string.punctuation).startswith(('http://', 'https://')):
                filtered_urls.append(url)
        
        return filtered_urls

