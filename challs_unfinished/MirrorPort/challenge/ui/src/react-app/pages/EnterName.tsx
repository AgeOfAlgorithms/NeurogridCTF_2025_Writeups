import { useState } from "react";
import { Terminal, Swords, ArrowRight } from "lucide-react";

interface EnterNameProps {
  onNameSubmit: (name: string) => void;
}

export default function EnterName({ onNameSubmit }: EnterNameProps) {
  const [name, setName] = useState("");

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (name.trim()) {
      onNameSubmit(name.trim());
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center px-4">
      <div className="max-w-md w-full">
        {/* Logo */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-20 h-20 bg-gradient-to-r from-red-600 to-indigo-600 rounded-2xl glow-red mb-4">
            <Swords className="w-10 h-10 text-white" />
          </div>
          <h1 className="font-cyber text-3xl font-bold bg-gradient-to-r from-red-400 via-yellow-400 to-indigo-400 bg-clip-text text-transparent text-glow-red mb-2">
            Scroll Marketplace
          </h1>
          <p className="text-gray-400 text-lg font-samurai">
            Enter your name to continue
          </p>
        </div>

        {/* Terminal-style welcome */}
        <div className="bg-gray-900/50 border border-red-500/30 rounded-lg p-6 mb-6 backdrop-blur-sm samurai-border">
          <div className="flex items-center space-x-2 mb-4">
            <Terminal className="w-5 h-5 text-yellow-400" />
            <span className="text-yellow-400 font-mono text-sm">SCROLL_WALLS_PROTOCOL</span>
          </div>
          <div className="space-y-2 text-sm font-mono">
            <p className="text-gray-300">
              <span className="text-red-400">&gt;</span> Preparing spirit...
            </p>
            <p className="text-gray-300">
              <span className="text-red-400">&gt;</span> Loading scroll database...
            </p>
            <p className="text-gray-300">
              <span className="text-red-400">&gt;</span> Samurai authentication required
            </p>
          </div>
        </div>

        {/* Name input form */}
        <form onSubmit={handleSubmit} className="space-y-6">
          <div>
            <label className="block text-sm font-medium font-samurai text-gray-300 mb-2">
              Name:
            </label>
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              className="w-full px-4 py-3 bg-gray-800/50 border border-red-500/30 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-red-400 focus:ring-2 focus:ring-red-400/20 transition-all duration-300"
              placeholder="Your honorable name..."
              required
              autoFocus
            />
          </div>

          <button
            type="submit"
            disabled={!name.trim()}
            className="w-full flex items-center justify-center space-x-2 px-6 py-3 bg-gradient-to-r from-red-600 to-indigo-600 text-white font-semibold font-samurai rounded-lg hover:from-red-700 hover:to-indigo-700 focus:outline-none focus:ring-2 focus:ring-red-500/50 disabled:opacity-50 disabled:cursor-not-allowed transition-all duration-300 glow-red hover:glow-gold"
          >
                        <span>Enter Marketplace</span>
            <ArrowRight className="w-5 h-5" />
          </button>
        </form>
      </div>
    </div>
  );
}
