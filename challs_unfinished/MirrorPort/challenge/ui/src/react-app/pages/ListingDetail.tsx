import { useState, useEffect } from "react";
import { useParams, Link } from "react-router";
import { ArrowLeft, User, Calendar, Coins, Swords } from "lucide-react";
import { marked } from "marked";
import type { Listing } from "@/shared/types";

export default function ListingDetail() {
  const { id } = useParams<{ id: string }>();
  const [listing, setListing] = useState<Listing | null>(null);
  const [processedNote, setProcessedNote] = useState<string>("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string>("");

  useEffect(() => {
    const fetchListing = async () => {
      if (!id) return;

      try {
        setLoading(true);
        
        // Fetch listing details
        const response = await fetch(`/api/listings/${id}`);
        if (!response.ok) {
          throw new Error("Listing not found");
        }
        const listingData = await response.json();
        setListing(listingData.listing || listingData);

        // Fetch processed note
        const noteResponse = await fetch(`/api/listings/${id}/processed-note`);
        if (noteResponse.ok) {
          const noteData = await noteResponse.json();
          setProcessedNote(noteData.processed_note || "");
        }
      } catch (error) {
        setError(error instanceof Error ? error.message : "Failed to load listing");
      } finally {
        setLoading(false);
      }
    };

    fetchListing();
  }, [id]);

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString("en-US", {
      year: "numeric",
      month: "long",
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

  if (error || !listing) {
    return (
      <div className="min-h-screen bg-transparent">
        <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
          <Link
            to="/"
            className="inline-flex items-center space-x-2 text-red-400 hover:text-red-300 transition-colors duration-300 mb-8 font-samurai"
          >
            <ArrowLeft className="w-5 h-5" />
            <span>Back to Marketplace</span>
          </Link>
          
          <div className="text-center py-12">
            <Swords className="w-16 h-16 text-gray-600 mx-auto mb-4" />
            <h3 className="text-xl font-semibold text-gray-400 mb-2 font-samurai">
              {error || "Scroll Not Found"}
            </h3>
            <p className="text-gray-500 font-samurai">
              The scroll you're looking for doesn't exist.
            </p>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-transparent">
      <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Back Button */}
        <Link
          to="/"
          className="inline-flex items-center space-x-2 text-red-400 hover:text-red-300 transition-colors duration-300 mb-8 font-samurai"
        >
          <ArrowLeft className="w-5 h-5" />
          <span>Back to Dojo</span>
        </Link>

        {/* Main Content */}
        <div className="bg-gray-800/50 border border-gray-700/50 rounded-lg overflow-hidden backdrop-blur-sm samurai-border">
          {/* Header */}
          <div className="p-6 border-b border-gray-700/50 gradient-bushido">
            <div className="flex flex-col lg:flex-row lg:items-start lg:justify-between mb-4">
              <div className="flex-1">
                <h1 className="font-cyber text-3xl font-bold text-white mb-3 text-glow-red">
                  {listing.scroll_name}
                </h1>
                <div className="flex flex-wrap items-center gap-4 text-sm text-gray-400">
                  <div className="flex items-center space-x-1">
                    <User className="w-4 h-4" />
                    <span className="font-samurai">Created by {listing.seller_name}</span>
                    <span className="text-red-400/60">Master</span>
                  </div>
                  <div className="flex items-center space-x-1">
                    <Calendar className="w-4 h-4" />
                    <span className="font-samurai">{formatDate(listing.created_at)}</span>
                  </div>
                  {listing.is_processed && (
                    <span className="px-2 py-1 bg-indigo-600/20 text-indigo-400 text-xs rounded-full border border-indigo-500/30 font-samurai">
                      Mastered
                    </span>
                  )}
                </div>
              </div>
              
              <div className="mt-4 lg:mt-0">
                <div className="flex items-center space-x-2 px-6 py-3 bg-red-600/20 border border-red-500/30 rounded-lg glow-red">
                  <Coins className="w-6 h-6 text-red-400" />
                  <span className="text-2xl font-bold text-red-400 font-samurai">
                    {listing.price} Gold
                  </span>
                </div>
              </div>
            </div>
          </div>

          {/* Image */}
          {listing.image_url && (
            <div className="p-6 border-b border-gray-700/50">
              <img
                src={listing.image_url}
                alt={listing.scroll_name}
                className="w-full max-h-96 object-contain rounded-lg border border-gray-700/50 bg-gray-900/50"
              />
            </div>
          )}

          {/* Description */}
          {listing.description && (
            <div className="p-6 border-b border-gray-700/50">
              <h2 className="text-xl font-semibold text-red-400 mb-3 font-samurai">
                Description
              </h2>
              <p className="text-gray-300 text-lg leading-relaxed font-samurai">
                {listing.description}
              </p>
            </div>
          )}

          {/* Notes */}
          {(processedNote || listing.note) && (
            <div className="p-6">
              <h2 className="text-xl font-semibold text-red-400 mb-4 font-samurai">
                Detailed Teachings
              </h2>
              <div className="bg-gray-900/50 border border-gray-700/30 rounded-lg p-6">
                <div 
                  className="prose prose-invert prose-red max-w-none font-samurai"
                  dangerouslySetInnerHTML={{ 
                    __html: marked(processedNote || listing.note || "") 
                  }}
                />
              </div>
            </div>
          )}


        </div>
      </div>
    </div>
  );
}
