import { useState, useEffect } from "react";
import { Trash2, Eye, EyeOff, Swords, Coins, Calendar, ChevronDown, ChevronUp } from "lucide-react";
import { marked } from "marked";
import type { Listing } from "@/shared/types";

interface OrdersProps {
  username: string;
}

export default function Orders({ username }: OrdersProps) {
  const [listings, setListings] = useState<Listing[]>([]);
  const [loading, setLoading] = useState(true);
  const [expandedNotes, setExpandedNotes] = useState<Set<number>>(new Set());
  const [deletingIds, setDeletingIds] = useState<Set<number>>(new Set());

  const fetchMyListings = async () => {
    try {
      const response = await fetch(`/api/listings/my?seller_name=${encodeURIComponent(username)}`);
      const data = await response.json();
      setListings(data.listings || []);
    } catch (error) {
      console.error("Failed to fetch my listings:", error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchMyListings();
    const interval = setInterval(fetchMyListings, 5000);
    return () => clearInterval(interval);
  }, [username]);

  const handleDelete = async (listingId: number) => {
    if (!confirm("Are you sure you want to delete this scroll? This action cannot be undone.")) {
      return;
    }

    setDeletingIds(prev => new Set([...prev, listingId]));

    try {
      const response = await fetch(`/api/listings/${listingId}?seller_name=${encodeURIComponent(username)}`, {
        method: "DELETE",
      });

      if (response.ok) {
        setListings(prev => prev.filter(listing => listing.id !== listingId));
      }
    } catch (error) {
      console.error("Failed to delete listing:", error);
    } finally {
      setDeletingIds(prev => {
        const newSet = new Set(prev);
        newSet.delete(listingId);
        return newSet;
      });
    }
  };

  const toggleNoteExpansion = (listingId: number) => {
    setExpandedNotes(prev => {
      const newSet = new Set(prev);
      if (newSet.has(listingId)) {
        newSet.delete(listingId);
      } else {
        newSet.add(listingId);
      }
      return newSet;
    });
  };

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString("en-US", {
      year: "numeric",
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
      <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Header */}
        <div className="mb-8">
          <h1 className="font-cyber text-3xl font-bold text-red-400 text-glow-red mb-2">
            My Listings
          </h1>
          <p className="text-gray-400 font-samurai">
            Manage your scroll listings
          </p>
        </div>

        {/* Stats */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
          <div className="bg-gray-800/50 border border-red-500/30 rounded-lg p-6 backdrop-blur-sm samurai-border">
            <div className="flex items-center space-x-3">
              <div className="p-2 bg-red-600/20 rounded-lg">
                <Swords className="w-6 h-6 text-red-400" />
              </div>
              <div>
                <p className="text-sm text-gray-400 font-samurai">Total Scrolls</p>
                <p className="text-2xl font-bold text-white">{listings.length}</p>
              </div>
            </div>
          </div>

          <div className="bg-gray-800/50 border border-red-500/30 rounded-lg p-6 backdrop-blur-sm samurai-border">
            <div className="flex items-center space-x-3">
              <div className="p-2 bg-red-600/20 rounded-lg">
                <Coins className="w-6 h-6 text-red-400" />
              </div>
              <div>
                <p className="text-sm text-gray-400 font-samurai">Total Value</p>
                <p className="text-2xl font-bold text-white">
                  {listings.reduce((sum, listing) => sum + listing.price, 0).toFixed(2)}
                </p>
              </div>
            </div>
          </div>

          <div className="bg-gray-800/50 border border-red-500/30 rounded-lg p-6 backdrop-blur-sm samurai-border">
            <div className="flex items-center space-x-3">
              <div className="p-2 bg-red-600/20 rounded-lg">
                <Eye className="w-6 h-6 text-red-400" />
              </div>
              <div>
                <p className="text-sm text-gray-400 font-samurai">Mastered</p>
                <p className="text-2xl font-bold text-white">
                  {listings.filter(l => l.is_processed).length}
                </p>
              </div>
            </div>
          </div>
        </div>

        {/* Listings */}
        <div className="space-y-6">
          {listings.map((listing) => (
            <div
              key={listing.id}
              className="bg-gray-800/50 border border-gray-700/50 rounded-lg overflow-hidden backdrop-blur-sm hover:border-red-500/50 transition-all duration-300 samurai-border"
            >
              <div className="p-6">
                {/* Header */}
                <div className="flex flex-col lg:flex-row lg:items-start lg:justify-between mb-4">
                  <div className="flex-1">
                    <div className="flex items-center space-x-3 mb-2">
                      <h3 className="text-xl font-semibold text-white font-samurai">
                        {listing.scroll_name}
                      </h3>
                      <div className="flex items-center space-x-1 text-red-400 font-bold">
                        <Coins className="w-4 h-4" />
                        <span>{listing.price}</span>
                      </div>
                      {listing.is_processed && (
                        <span className="px-2 py-1 bg-red-600/20 text-red-400 text-xs rounded-full border border-red-500/30 font-samurai">
                          Mastered
                        </span>
                      )}
                    </div>
                    <div className="flex items-center space-x-1 text-gray-500 text-sm">
                      <Calendar className="w-4 h-4" />
                      <span className="font-samurai">Created {formatDate(listing.created_at)}</span>
                    </div>
                  </div>
                  
                  <button
                    onClick={() => handleDelete(listing.id)}
                    disabled={deletingIds.has(listing.id)}
                    className="mt-4 lg:mt-0 flex items-center space-x-2 px-4 py-2 bg-red-600/20 text-red-400 rounded-lg hover:bg-red-600/30 hover:text-red-300 disabled:opacity-50 disabled:cursor-not-allowed transition-all duration-300 border border-red-500/30 font-samurai"
                  >
                    <Trash2 className="w-4 h-4" />
                    <span>{deletingIds.has(listing.id) ? "Deleting..." : "Delete"}</span>
                  </button>
                </div>

                {/* Image */}
                {listing.image_url && (
                  <div className="mb-4">
                    <img
                      src={listing.image_url}
                      alt={listing.scroll_name}
                      className="w-full h-48 object-cover rounded-lg border border-gray-700/50"
                    />
                  </div>
                )}

                {/* Description */}
                {listing.description && (
                  <div className="mb-4">
                    <p className="text-gray-300 font-samurai">{listing.description}</p>
                  </div>
                )}

                {/* Note */}
                {listing.note && (
                  <div className="border-t border-gray-700/50 pt-4">
                    <button
                      onClick={() => toggleNoteExpansion(listing.id)}
                      className="flex items-center space-x-2 text-red-400 hover:text-red-300 transition-colors duration-300 mb-3 font-samurai"
                    >
                      {expandedNotes.has(listing.id) ? (
                        <>
                          <EyeOff className="w-4 h-4" />
                          <span>Hide Teachings</span>
                          <ChevronUp className="w-4 h-4" />
                        </>
                      ) : (
                        <>
                          <Eye className="w-4 h-4" />
                          <span>Show Teachings</span>
                          <ChevronDown className="w-4 h-4" />
                        </>
                      )}
                    </button>

                    {expandedNotes.has(listing.id) && (
                      <div className="bg-gray-900/50 border border-gray-700/30 rounded-lg p-4">
                        <div 
                          className="prose prose-invert prose-red max-w-none text-sm font-samurai"
                          dangerouslySetInnerHTML={{ __html: marked(listing.note) }}
                        />
                      </div>
                    )}
                  </div>
                )}
              </div>
            </div>
          ))}
        </div>

        {listings.length === 0 && !loading && (
          <div className="text-center py-12">
            <Swords className="w-16 h-16 text-gray-600 mx-auto mb-4" />
            <h3 className="text-xl font-semibold text-gray-400 mb-2 font-samurai">
              No Listings
            </h3>
            <p className="text-gray-500 mb-6 font-samurai">
              You haven't created any listings yet. Create your first listing to get started.
            </p>
            <a
              href="/"
              className="inline-flex items-center space-x-2 px-6 py-3 bg-red-600 text-white font-semibold font-samurai rounded-lg hover:bg-red-700 transition-all duration-300 glow-red"
            >
              <Swords className="w-5 h-5" />
              <span>Create Listing</span>
            </a>
          </div>
        )}
      </div>
    </div>
  );
}
