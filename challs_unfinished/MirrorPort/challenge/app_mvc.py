#!/usr/bin/env python3
"""
Hōgetsu Teahouse - Smoke Behind Paper Walls
A Flask application following MVC architecture for the HTB challenge.

In the merchant port of Hōgetsu, an innkeeper offers sanctuary in a fading teahouse 
built above a floating market. But Ayame notices too much: duplicated signage, 
stalls that close yet never sell, the same patrons sipping untouched cups night 
after night. She wanders the upper halls while the town sleeps, watching lanterns 
flicker out of rhythm. Hidden above the bathhouse ceiling is a crawlspace webbed 
with silken scrolls and faded seals—each one masking contracts, debts, and 
accusations buried years ago. Ayame begins to map the invisible hands pulling 
strings from behind rice-paper walls, realizing that to unmask the truth, she 
must step into the web and not get caught.
"""

import os
import redis
from flask import Flask
from config.app_config import Config
from routes.api import api_bp
from routes.main import main_bp
from models.listing import Listing
from models.session import SessionManager


def create_app():
    """Create and configure the Flask application."""
    app = Flask(__name__, 
                static_folder=Config.STATIC_FOLDER, 
                static_url_path=Config.STATIC_URL_PATH)
    
    # Configure Flask
    app.config.from_object(Config)
    
    # Register blueprints
    app.register_blueprint(api_bp)
    app.register_blueprint(main_bp)
    
    # Add markdown filter to Jinja environment
    import markdown
    def markdown_filter(text):
        return markdown.markdown(text, extensions=['extra'])
    
    app.jinja_env.filters['markdown'] = markdown_filter
    
    # Initialize default listings
    initialize_default_listings()
    
    return app


def initialize_default_listings():
    """Initialize default listings on application startup."""
    try:
        existing_listings = SessionManager.get_all_listings()
        existing_scroll_names = {listing.scroll_name for listing in existing_listings}
        
        # Define all default scrolls
        default_scrolls = [
            {
                'scroll_name': 'Scroll of Shadow',
                'seller_name': 'Ancient Archive',
                'price': 5000.00,
                'description': """Item Type: Legendary Artifact
Aura: Overwhelming (Shadow, Divination, and Illusion)

This ancient scroll is bound not by simple leather, but by tendrils of solidified shadow that seem to writhe with a life of their own. The parchment itself is a deep, bruised purple, crafted from an unknown, leathery hide that feels unnervingly cold to the touch.

Glowing, angular runes are etched across its surface, pulsing with a faint, violet light. They seem to shift and rewrite themselves when viewed from the corner of the eye, hinting at the forbidden and chaotic knowledge contained within.

The scroll is sealed by a horrifying clasp: a single, glowing purple eye, reptilian and all-seeing, set within a dark, metallic frame. The eye swivels to watch any who draw near, a silent guardian of the dark secrets it holds.

Wisps of ethereal shadow smoke constantly leak from the scroll's edges, whispering unintelligible secrets to those who dare to listen. It rests upon a dark, runic pedestal, surrounded by the bones of those who failed to control its power, waiting for its next master.""",
                'image_url': '/backend-assets/shadow-scroll.jpeg',
                'note': '',
                'urls': []
            },
            {
                'scroll_name': 'Scroll of Eternal Flame',
                'seller_name': 'Master Chen',
                'price': 3200.00,
                'description': """Item Type: Rare Artifact
Aura: Strong (Evocation, Fire)

Wrapped in smoldering crimson silk that never seems to burn, this scroll glows with an inner fire that pulses like a heartbeat. The parchment is made from the hide of a phoenix, still warm to the touch and resistant to all flames. Golden characters written in ancient draconic script dance across its surface, occasionally sparking with small embers.

The scroll is secured by a bronze clasp shaped like a coiled dragon, its ruby eyes gleaming with captured flame. When unfurled, the text appears to be written in liquid fire, constantly shifting and reforming. The air around it shimmers with heat, and nearby candles flicker and flare in its presence.

Whispers of this scroll speak of masters who learned to command infernos, but also of those who became consumed by their own flames. It is said that the scroll chooses its wielder, testing them with visions of destruction before revealing its true power.""",
                'image_url': '/backend-assets/flame-scroll.jpeg',
                'note': '',
                'urls': []
            },
            {
                'scroll_name': 'Scroll of Silent Winds',
                'seller_name': 'Whispering Breeze Monastery',
                'price': 2800.00,
                'description': """Item Type: Rare Artifact
Aura: Moderate (Air, Transmutation)

This ethereal scroll appears almost transparent, woven from threads of condensed mist and morning dew. It hovers slightly above any surface it rests upon, never quite touching the ground. The calligraphy is formed from wisps of cloud and smoke, constantly shifting but always legible.

Bound with a silver cord that chimes like wind chimes, the scroll moves with an unseen breeze even in still air. The characters are written in the language of air elementals, and those who read it report hearing distant melodies on winds that carry secrets from mountain peaks and storm clouds.

The scroll is kept in a bamboo cylinder decorated with carvings of birds in flight. When opened, it releases the scent of rain-washed forests and high-altitude air. Masters of the wind arts seek this scroll to learn techniques of flight, invisibility, and storm calling.""",
                'image_url': '/backend-assets/wind-scroll.jpeg',
                'note': '',
                'urls': []
            },
            {
                'scroll_name': 'Scroll of Sacred Bloom',
                'seller_name': 'Sakura Grove Temple',
                'price': 2400.00,
                'description': """Item Type: Uncommon Artifact
Aura: Moderate (Conjuration, Healing)

Crafted from the bark of the legendary Eternal Cherry Tree, this scroll is perpetually in bloom. Delicate pink cherry blossoms sprout along its edges and fall continuously, only to regrow moments later. The parchment itself is green-tinted and fibrous, like living plant matter, yet supple as silk.

The text is written in sap that glistens with healing light, and faint floral patterns weave between the characters. The scroll is tied with a living vine that slowly grows new leaves, occasionally producing small white flowers that fill the air with a calming fragrance.

Those who meditate near this scroll find their wounds healing faster and their spirits lifted. It is said to contain knowledge of ancient healing techniques and methods to commune with nature spirits. The scroll responds to life force, glowing brighter when in the presence of those who protect life.""",
                'image_url': '/backend-assets/bloom-scroll.jpeg',
                'note': '',
                'urls': []
            },
            {
                'scroll_name': 'Scroll of Twilight Whispers',
                'seller_name': 'Veiled Merchant',
                'price': 4500.00,
                'description': """Item Type: Very Rare Artifact
Aura: Strong (Enchantment, Illusion)

This mysterious scroll exists in a state of perpetual dusk. It appears to be made of solidified twilight, with colors shifting between deep purple, indigo, and shadowy gray. The text itself seems to be written in starlight, visible only when viewed from certain angles, and completely invisible in direct sunlight.

The scroll is secured with a clasp made from captured moonlight and shadow, which appears differently to each viewer. Some see a crescent moon, others a closed eye, and still others see nothing at all. When opened, the scroll releases gentle whispers that speak directly to the mind, bypassing the ears entirely.

The knowledge within deals with the manipulation of perception, memory, and truth. Those who study it learn to weave illusions so convincing they become reality, and to speak words that command absolute obedience. However, the scroll's whispers grow stronger over time, and some scholars have been driven to madness trying to silence them.""",
                'image_url': '/backend-assets/twilight-scroll.jpeg',
                'note': '',
                'urls': []
            },
            {
                'scroll_name': 'Scroll of Mountain\'s Wisdom',
                'seller_name': 'Stone Hermit',
                'price': 1800.00,
                'description': """Item Type: Uncommon Artifact
Aura: Moderate (Abjuration, Earth)

This heavy scroll is carved into a single slab of jade-colored stone, yet somehow remains flexible enough to roll and unroll. The characters are chiseled deep into the surface and filled with molten gold that never cools, creating a warm, glowing script. Small crystals grow along its edges, sparkling like stars in rock.

The scroll is bound with iron bands engraved with runes of protection and endurance. It feels impossibly dense when held, as if it weighs far more than its size suggests. The stone itself seems to pulse slowly, like a heartbeat deep within a mountain.

This scroll contains the accumulated wisdom of generations of mountain hermits and earth monks. It teaches techniques of unbreakable defense, unshakeable resolve, and the patience of stone. The knowledge within ages like fine stone, becoming more valuable with time.""",
                'image_url': '/backend-assets/mountain-scroll.jpeg',
                'note': '',
                'urls': []
            },
            {
                'scroll_name': 'Scroll of Crimson Moon',
                'seller_name': 'Night Market Vendor',
                'price': 3800.00,
                'description': """Item Type: Rare Artifact
Aura: Strong (Necromancy, Divination)

Wrapped in fabric dyed the color of blood and starlight, this scroll seems to pulse with an ominous rhythm. The parchment is made from the skin of a creature that should not exist, pale and unnaturally smooth, marked with veins that occasionally twitch. The text is written in ink that appears black in daylight but glows deep crimson under moonlight.

The scroll is sealed with a silver crescent moon pendant that drips with what looks like blood but never stains. When the moon is full, the scroll becomes restless, and the text rearranges itself to reveal new secrets. Under a new moon, it becomes dormant and appears almost dead.

This scroll contains forbidden knowledge of life, death, and the spaces between. It speaks of communing with spirits, reading omens in shadows, and understanding the price of power. Those who use it find their fate becomes intertwined with lunar cycles, and some claim the scroll drinks their dreams.""",
                'image_url': '/backend-assets/crimson-moon-scroll.jpeg',
                'note': '',
                'urls': []
            },
            {
                'scroll_name': 'Scroll of Flowing Water',
                'seller_name': 'River Sage',
                'price': 2200.00,
                'description': """Item Type: Uncommon Artifact
Aura: Moderate (Transmutation, Water)

This scroll appears to be made entirely of flowing water, somehow contained within an invisible frame that keeps it in scroll form. The liquid within constantly moves, creating ripples and currents that form characters and patterns. The text flows across the surface like a stream, changing and adapting as it moves.

It is secured with a clasp carved from a single piece of blue jade shaped like a koi fish. When the scroll is opened, the sound of gentle waterfalls and babbling brooks can be heard. The water within never spills, always maintaining its form, and reflects light in mesmerizing patterns.

The knowledge within teaches the principles of adaptability, flow, and persistence. It contains techniques for shaping water, understanding currents both physical and metaphorical, and finding the path of least resistance. The scroll seems to respond to calm emotions, becoming turbulent when near those filled with anger or fear.""",
                'image_url': '/backend-assets/water-scroll.jpeg',
                'note': '',
                'urls': []
            },
            {
                'scroll_name': 'The Aetherium Scroll of Genesis and Ruin',
                'seller_name': 'The Void Merchant',
                'price': 15000.00,
                'description': """Item Type: Legendary Artifact
Aura: Overwhelming (Universal, Creation, Destruction)

This scroll is not merely parchment, but a shimmering tapestry woven from the fabric of existence itself. It appears as an endless void flecked with distant galaxies and swirling nebulae, yet can be held in one's hand. Its edges are constantly forming and dissolving, as if mirroring the birth and death of stars. The text inscribed upon it is not static; it is composed of pure cosmic energy, shifting between the radiant light of creation and the crushing darkness of oblivion, comprehensible only to a mind capable of perceiving absolute truth.

It is bound by nothing less than a miniature singularity, held in perfect, stable suspension, radiating both the immense gravitational pull of a collapsing star and the dazzling output of a newborn sun. This singularity hums with a silent, profound power that can be felt in the very bones of any creature nearby. When unrolled, the scroll unfolds into an infinite expanse, revealing not just words, but entire universes expanding and contracting within its surface. The ambient sound around it becomes a symphony of cosmic forces – the silent hum of dark matter, the roar of solar flares, and the whispered echoes of civilizations long past.

The Aetherium Scroll contains the fundamental blueprints of reality, the very equations that govern existence. It offers control over causality, the ability to weave new realities, or unravel existing ones. It holds the power to bestow ultimate life or ultimate oblivion, to reshape the laws of physics, or to simply erase them. However, wielding it is akin to holding the universe in one's bare hands; its power is so immense that any attempt to utilize it without absolute understanding and control risks unraveling the wielder, their world, or indeed, reality itself. Legends speak of only one being ever truly mastering it, and that being is said to have ascended beyond the need for physical form, becoming one with the cosmos.""",
                'image_url': '/backend-assets/aetherium-scroll.jpeg',
                'note': '',
                'urls': []
            }
        ]
        
        # Create listings for scrolls that don't already exist
        for scroll_data in default_scrolls:
            if scroll_data['scroll_name'] not in existing_scroll_names:
                listing_id = SessionManager.get_next_listing_id()
                listing = Listing(
                    id=listing_id,
                    seller_name=scroll_data['seller_name'],
                    scroll_name=scroll_data['scroll_name'],
                    price=scroll_data['price'],
                    description=scroll_data['description'],
                    note=scroll_data['note'],
                    urls=scroll_data['urls'],
                    image_url=scroll_data['image_url'],
                    is_processed=False
                )
                SessionManager.add_listing(listing)
            
    except Exception as e:
        # Silently fail if initialization doesn't work (Redis might not be ready yet)
        print(f"Warning: Could not initialize default listings: {e}")


def check_redis_connection():
    """Check Redis connection before starting the app."""
    try:
        redis_client = redis.Redis(
            host=Config.REDIS_HOST, 
            port=Config.REDIS_PORT, 
            db=Config.REDIS_DB, 
            decode_responses=Config.REDIS_DECODE_RESPONSES
        )
        redis_client.ping()
        return True
    except redis.ConnectionError:
        return False
