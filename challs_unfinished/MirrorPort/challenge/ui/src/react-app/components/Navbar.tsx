import { Link, useLocation } from "react-router";
import { User, LogOut, Swords } from "lucide-react";

interface NavbarProps {
  username: string;
  onLogout: () => void;
}

export default function Navbar({ username, onLogout }: NavbarProps) {
  const location = useLocation();

  return (
    <nav className="bg-gray-900/90 backdrop-blur-md border-b border-red-500/30 sticky top-0 z-50">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex justify-between items-center h-16">
          {/* Logo */}
          <Link to="/" className="flex items-center space-x-2 group">
            <div className="p-2 bg-red-600 rounded-lg glow-red transition-all duration-300">
              <Swords className="w-6 h-6 text-white" />
            </div>
            <span className="font-cyber text-xl font-bold text-red-400 text-glow-red">
              Scroll Marketplace
            </span>
          </Link>

          {/* Remove spacer; we'll right-align via ml-auto on the right group */}

          {/* Right side: nav links + user menu */}
          <div className="ml-auto flex items-center space-x-4">
            <div className="flex items-center space-x-3 mr-2">
              <Link
                to="/"
                className={`px-4 py-2 rounded-lg font-medium font-samurai transition-all duration-300 ${
                  location.pathname === "/"
                    ? "bg-red-600/20 text-red-400 border border-red-500/50 glow-red"
                    : "text-gray-300 hover:text-red-400 hover:bg-red-600/10"
                }`}
              >
                Create Listing
              </Link>
              <Link
                to="/orders"
                className={`px-4 py-2 rounded-lg font-medium font-samurai transition-all duration-300 ${
                  location.pathname === "/orders"
                    ? "bg-red-600/20 text-red-400 border border-red-500/50 glow-red"
                    : "text-gray-300 hover:text-red-400 hover:bg-red-600/10"
                }`}
              >
                My Listings
              </Link>
            </div>
            <div className="flex items-center space-x-2 px-3 py-2 bg-gray-800/50 rounded-lg border border-gray-700/50">
              <User className="w-4 h-4 text-red-400" />
              <span className="text-sm font-medium font-samurai text-gray-300">{username}</span>
              <span className="text-xs text-gray-500">Samurai</span>
            </div>
            <button
              onClick={onLogout}
              className="p-2 text-gray-400 hover:text-red-400 hover:bg-red-600/10 rounded-lg transition-all duration-300"
              title="Logout"
            >
              <LogOut className="w-5 h-5" />
            </button>
          </div>
        </div>
      </div>
    </nav>
  );
}
