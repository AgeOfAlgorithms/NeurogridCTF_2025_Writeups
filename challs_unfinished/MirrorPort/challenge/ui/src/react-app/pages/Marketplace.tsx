import { useState, useEffect } from "react";
import { Link } from "react-router";
import { Search, Plus, X, Eye, Swords, Coins, User, Calendar } from "lucide-react";
import { marked } from "marked";
import type { Listing, CreateListing } from "@/shared/types";

interface MarketplaceProps {
  username: string;
}

export default function Marketplace({ username }: MarketplaceProps) {
  const [listings, setListings] = useState<Listing[]>([]);
  const [searchTerm, setSearchTerm] = useState("");
  const [showCreateForm, setShowCreateForm] = useState(false);
  const [loading, setLoading] = useState(true);
  const [creating, setCreating] = useState(false);

  // Form state
  const [formData, setFormData] = useState<CreateListing>({
    seller_name: username,
    scroll_name: "",
    price: 0,
    description: "",
    note: "",
    image_url: "",
  });
  
  const [imagePreview, setImagePreview] = useState<string>("");
  const [showNotePreview, setShowNotePreview] = useState(false);

  // Fetch listings
  const fetchListings = async () => {
    try {
      const response = await fetch("/api/listings");
      const data = await response.json();
      setListings(data.listings || []);
    } catch (error) {
      console.error("Failed to fetch listings:", error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchListings();
    const interval = setInterval(fetchListings, 5000);
    return () => clearInterval(interval);
  }, []);

  // Sync seller_name with username prop
  useEffect(() => {
    setFormData(prev => ({
      ...prev,
      seller_name: username
    }));
  }, [username]);

  // Handle image upload
  const handleImageUpload = async (file: File) => {
    const formData = new FormData();
    formData.append("image", file);

    try {
      const response = await fetch("/api/upload/image", {
        method: "POST",
        body: formData,
      });
      const data = await response.json();
      
      if (data.success) {
        setFormData(prev => ({ ...prev, image_url: data.image_url }));
        setImagePreview(data.image_url);
      }
    } catch (error) {
      console.error("Failed to upload image:", error);
    }
  };

  // Handle form submission
  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setCreating(true);

    try {
      // Ensure seller_name is always set to current username
      const submissionData = {
        ...formData,
        seller_name: username
      };
      
      const response = await fetch("/api/listings", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(submissionData),
      });

      if (response.ok) {
        setShowCreateForm(false);
        setFormData({
          seller_name: username,
          scroll_name: "",
          price: 0,
          description: "",
          note: "",
          image_url: "",
        });
        
        setImagePreview("");
        fetchListings();
      }
    } catch (error) {
      console.error("Failed to create listing:", error);
    } finally {
      setCreating(false);
    }
  };

  const filteredListings = listings.filter(listing =>
    listing.scroll_name.toLowerCase().includes(searchTerm.toLowerCase()) ||
    listing.description?.toLowerCase().includes(searchTerm.toLowerCase()) ||
    listing.seller_name.toLowerCase().includes(searchTerm.toLowerCase())
  );

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString("en-US", {
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    });
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="animate-spin">
          <Swords className="w-10 h-10 text-red-400" />
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-transparent">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Header */}
        <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between mb-8">
          <div>
            <h1 className="font-cyber text-3xl font-bold text-red-400 text-glow-red mb-1">
              Marketplace
            </h1>
            <p className="text-gray-400 font-samurai">
              Browse and sell scrolls
            </p>
          </div>
          <button
            onClick={() => setShowCreateForm(true)}
            className="mt-4 lg:mt-0 flex items-center space-x-2 px-6 py-3 bg-red-600 text-white font-semibold font-samurai rounded-lg hover:bg-red-700 transition-all duration-300 glow-red"
          >
            <Plus className="w-5 h-5" />
            <span>Create Listing</span>
          </button>
        </div>

        {/* Search */}
        <div className="relative mb-8">
          <Search className="absolute left-4 top-1/2 transform -translate-y-1/2 w-5 h-5 text-gray-400" />
          <input
            type="text"
            placeholder="Search scrolls, sellers, descriptions..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full pl-12 pr-4 py-3 bg-gray-800/50 border border-red-500/30 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-red-400 focus:ring-2 focus:ring-red-400/20 transition-all duration-300 font-samurai"
          />
        </div>

        {/* Listings Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {filteredListings.map((listing) => (
            <Link
              key={listing.id}
              to={`/listing/${listing.id}`}
              className="group block"
            >
              <div className="bg-gray-800/50 border border-gray-700/50 rounded-lg overflow-hidden hover:border-red-500/50 hover:glow-red transition-all duration-300 backdrop-blur-sm samurai-border">
                {/* Image */}
                {listing.image_url && (
                  <div className="aspect-video overflow-hidden">
                    <img
                      src={listing.image_url}
                      alt={listing.scroll_name}
                      className="w-full h-full object-cover group-hover:scale-105 transition-transform duration-300"
                    />
                  </div>
                )}

                <div className="p-6">
                  {/* Title and Price */}
                  <div className="flex justify-between items-start mb-3">
                    <h3 className="font-semibold text-lg text-white font-samurai group-hover:text-red-400 transition-colors duration-300 line-clamp-2">
                      {listing.scroll_name}
                    </h3>
                    <div className="flex items-center space-x-1 text-yellow-400 font-bold text-lg ml-2">
                      <Coins className="w-4 h-4" />
                      <span>{listing.price}</span>
                    </div>
                  </div>

                  {/* Description */}
                  {listing.description && (
                    <p className="text-gray-400 text-sm mb-4 line-clamp-2 font-samurai">
                      {listing.description}
                    </p>
                  )}

                  {/* Seller and Date */}
                  <div className="flex justify-between items-center text-sm text-gray-500">
                    <div className="flex items-center space-x-1">
                      <User className="w-4 h-4" />
                      <span className="font-samurai">{listing.seller_name}</span>
                      <span className="text-xs text-red-400/60">Master</span>
                    </div>
                    <div className="flex items-center space-x-1">
                      <Calendar className="w-4 h-4" />
                      <span>{formatDate(listing.created_at)}</span>
                    </div>
                  </div>
                </div>
              </div>
            </Link>
          ))}
        </div>

        {filteredListings.length === 0 && !loading && (
          <div className="text-center py-12">
            <Swords className="w-16 h-16 text-gray-600 mx-auto mb-4" />
            <h3 className="text-xl font-semibold text-gray-400 mb-2 font-samurai">
              {searchTerm ? 'No Listings Found' : 'No Listings Yet'}
            </h3>
            <p className="text-gray-500 font-samurai">
              {searchTerm ? "Try different search terms" : "Be the first to list a scroll in the marketplace!"}
            </p>
          </div>
        )}
      </div>

      {/* Create Form Modal */}
      {showCreateForm && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4 z-50">
          <div className="bg-gray-900/95 border border-red-500/30 rounded-lg max-w-2xl w-full max-h-[90vh] overflow-y-auto scrollbar-thin samurai-border">
            <div className="p-6">
              <div className="flex justify-between items-center mb-6">
                <h2 className="font-cyber text-2xl font-bold text-red-400">
                  Create New Listing
                </h2>
                <button
                  onClick={() => setShowCreateForm(false)}
                  className="p-2 text-gray-400 hover:text-white rounded-lg hover:bg-gray-700/50 transition-all duration-300"
                >
                  <X className="w-6 h-6" />
                </button>
              </div>

              <form onSubmit={handleSubmit} className="space-y-6">
                {/* Scroll Name */}
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2 font-samurai">
                    Scroll Name *
                  </label>
                  <input
                    type="text"
                    value={formData.scroll_name}
                    onChange={(e) => setFormData(prev => ({ ...prev, scroll_name: e.target.value }))}
                    className="w-full px-4 py-3 bg-gray-800/50 border border-gray-700/50 rounded-lg text-white focus:outline-none focus:border-red-400 focus:ring-2 focus:ring-red-400/20 transition-all duration-300 font-samurai"
                    placeholder="Ancient Technique of..."
                    required
                  />
                </div>

                {/* Price */}
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2 font-samurai">
                    Price (Gold) *
                  </label>
                  <input
                    type="number"
                    min="0"
                    step="0.01"
                    value={formData.price}
                    onChange={(e) => setFormData(prev => ({ ...prev, price: parseFloat(e.target.value) || 0 }))}
                    className="w-full px-4 py-3 bg-gray-800/50 border border-gray-700/50 rounded-lg text-white focus:outline-none focus:border-red-400 focus:ring-2 focus:ring-red-400/20 transition-all duration-300 font-samurai"
                    required
                  />
                </div>

                {/* Description */}
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2 font-samurai">
                    Description
                  </label>
                  <textarea
                    value={formData.description}
                    onChange={(e) => setFormData(prev => ({ ...prev, description: e.target.value }))}
                    className="w-full px-4 py-3 bg-gray-800/50 border border-gray-700/50 rounded-lg text-white focus:outline-none focus:border-red-400 focus:ring-2 focus:ring-red-400/20 transition-all duration-300 font-samurai"
                    rows={3}
                    placeholder="Brief description of the scroll's teachings..."
                  />
                </div>

                {/* Note with Preview */}
                <div>
                  <div className="flex justify-between items-center mb-2">
                    <label className="block text-sm font-medium text-gray-300 font-samurai">
                      Detailed Teachings (Markdown supported)
                    </label>
                    <button
                      type="button"
                      onClick={() => setShowNotePreview(!showNotePreview)}
                      className="flex items-center space-x-1 text-sm text-red-400 hover:text-red-300 transition-colors duration-300"
                    >
                      <Eye className="w-4 h-4" />
                      <span>{showNotePreview ? "Hide" : "Show"} Preview</span>
                    </button>
                  </div>
                  <div className="grid grid-cols-1 gap-4">
                    <textarea
                      value={formData.note}
                      onChange={(e) => setFormData(prev => ({ ...prev, note: e.target.value }))}
                      className="w-full px-4 py-3 bg-gray-800/50 border border-gray-700/50 rounded-lg text-white focus:outline-none focus:border-red-400 focus:ring-2 focus:ring-red-400/20 transition-all duration-300 font-samurai"
                      rows={4}
                      placeholder="# Ancient Wisdom&#10;&#10;Share the detailed teachings of your scroll..."
                    />
                    {showNotePreview && formData.note && (
                      <div className="bg-gray-800/30 border border-gray-700/30 rounded-lg p-4">
                        <h4 className="text-sm font-medium text-gray-300 mb-2 font-samurai">Preview:</h4>
                        <div 
                          className="prose prose-invert prose-red max-w-none text-sm font-samurai"
                          dangerouslySetInnerHTML={{ __html: marked(formData.note) }}
                        />
                      </div>
                    )}
                  </div>
                </div>

                {/* Image Upload */}
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2 font-samurai">
                    Scroll Image
                  </label>
                  <div className="space-y-4">
                    <input
                      type="file"
                      accept="image/*"
                      onChange={(e) => {
                        const file = e.target.files?.[0];
                        if (file) {
                          handleImageUpload(file);
                        }
                      }}
                      className="w-full px-4 py-3 bg-gray-800/50 border border-gray-700/50 rounded-lg text-white file:mr-4 file:py-2 file:px-4 file:rounded-lg file:border-0 file:text-sm file:bg-red-600 file:text-white hover:file:bg-red-700 file:cursor-pointer transition-all duration-300 font-samurai"
                    />
                    {imagePreview && (
                      <div className="relative">
                        <img
                          src={imagePreview}
                          alt="Preview"
                          className="w-full h-48 object-cover rounded-lg border border-gray-700/50"
                        />
                        <button
                          type="button"
                          onClick={() => {
                            setImagePreview("");
                            setFormData(prev => ({ ...prev, image_url: "" }));
                          }}
                          className="absolute top-2 right-2 p-1 bg-red-600 text-white rounded-full hover:bg-red-700 transition-colors duration-300"
                        >
                          <X className="w-4 h-4" />
                        </button>
                      </div>
                    )}
                  </div>
                </div>

                {/* Submit */}
                <div className="flex space-x-4 pt-4">
                  <button
                    type="button"
                    onClick={() => setShowCreateForm(false)}
                    className="flex-1 px-6 py-3 bg-gray-700 text-white rounded-lg hover:bg-gray-600 transition-colors duration-300 font-samurai"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    disabled={creating || !formData.scroll_name || formData.price < 0}
                    className="flex-1 px-6 py-3 bg-red-600 text-white font-semibold font-samurai rounded-lg hover:bg-red-700 disabled:opacity-50 disabled:cursor-not-allowed transition-all duration-300 glow-red"
                  >
                    {creating ? "Creating..." : "Create Listing"}
                  </button>
                </div>
              </form>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
