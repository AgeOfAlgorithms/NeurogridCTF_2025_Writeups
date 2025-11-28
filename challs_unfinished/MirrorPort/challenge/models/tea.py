"""
Scroll model for the Ninja Scroll Marketplace challenge.
Represents scrolls, spells, and jutsu available for purchase.
"""

from datetime import datetime
from typing import List, Dict, Optional


class Scroll:
    """Represents a scroll/spell/jutsu item in the marketplace."""
    
    def __init__(self, id: int, name: str, price: float, description: str, 
                 created_at: str = None, updated_at: str = None):
        self.id = id
        self.name = name
        self.price = price
        self.description = description
        self.created_at = created_at or datetime.now().isoformat()
        self.updated_at = updated_at or datetime.now().isoformat()
    
    def to_dict(self) -> Dict:
        """Convert scroll to dictionary for JSON serialization."""
        return {
            'id': self.id,
            'name': self.name,
            'price': self.price,
            'description': self.description,
            'created_at': self.created_at,
            'updated_at': self.updated_at
        }
    
    @staticmethod
    def get_all() -> List['Scroll']:
        """Get all available scrolls from the marketplace."""
        return [
            Scroll(1, 'Kage Bunshin no Jutsu', 1250, 
                'Shadow Clone Technique - Create multiple physical copies of yourself. Basic version for beginners.'),
            Scroll(2, 'Chidori', 1875, 
                'Lightning Release technique that concentrates electrical energy in the hand. Requires careful chakra control.'),
            Scroll(3, 'Rasengan', 1825, 
                'Spiral Sphere - A powerful technique that forms a rotating sphere of chakra. Advanced scroll with detailed instructions.'),
            Scroll(4, 'Katon: Gōkakyū no Jutsu', 1400, 
                'Fire Release: Great Fireball Technique. Signature Uchiha clan technique. Authentic scroll from Konoha archives.'),
            Scroll(5, 'Suiton: Suiryūdan no Jutsu', 1650, 
                'Water Release: Water Dragon Bullet. Summons a powerful water dragon. Popular among Mizukage followers.'),
            Scroll(6, 'Amaterasu', 2200, 
                'Heavenly Illumination - Black flames that burn until their target is completely destroyed. Legendary Mangekyo Sharingan technique.'),
            Scroll(7, 'Byakugan Activation Scroll', 1250, 
                'Instructions for awakening the Byakugan dojutsu. Includes meditation techniques and chakra circulation methods.'),
            Scroll(8, 'Sharingan Evolution Guide', 1580, 
                'Complete guide to evolving Sharingan through Tomoe stages. Contains historical records and training methods.'),
            Scroll(9, 'Fūinjutsu Basics', 1820, 
                'Sealing techniques for beginners. Learn to create storage scrolls and basic barrier seals. Essential for any ninja.'),
            Scroll(10, 'Summoning Contract Template', 1430, 
                'Template for establishing contracts with summoning animals. Includes blood oath rituals and negotiation techniques.'),
            Scroll(11, 'Genjutsu: Kai', 1360, 
                'Technique to break free from illusionary jutsu. Critical defensive skill for combating Sharingan users.')
        ]
    
    @staticmethod
    def find_by_id(scroll_id: int) -> Optional['Scroll']:
        """Find a scroll by its ID."""
        scrolls = Scroll.get_all()
        return next((scroll for scroll in scrolls if scroll.id == scroll_id), None)


