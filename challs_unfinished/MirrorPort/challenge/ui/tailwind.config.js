/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/react-app/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      fontFamily: {
        'cyber': ['Orbitron', 'monospace'],
        'samurai': ['Noto Sans JP', 'Rajdhani', 'sans-serif'],
        'sans': ['Rajdhani', 'Noto Sans JP', 'system-ui', 'sans-serif'],
      },
      colors: {
        // Samurai/Japanese inspired colors
        samurai: {
          red: '#dc2626',     // Deep red (aka/赤)
          gold: '#fbbf24',    // Gold (kin/金)  
          indigo: '#4338ca',  // Deep indigo (ai/藍)
          crimson: '#b91c1c', // Crimson
          amber: '#f59e0b',   // Amber
          navy: '#1e3a8a',    // Navy blue
        },
        // Legacy cyber colors for compatibility
        cyber: {
          purple: '#8b5cf6',
          blue: '#06b6d4',
          pink: '#ec4899',
          green: '#10b981',
        },
      },
      animation: {
        'pulse-glow': 'pulse 2s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'katana-slash': 'katana-slash 1.5s ease-in-out infinite',
        'cherry-blossom': 'cherry-blossom 3s ease-in-out infinite',
      },
      backdropBlur: {
        'xs': '2px',
      },
      boxShadow: {
        // Samurai themed glows
        'glow-red': '0 0 20px rgba(220, 38, 38, 0.6)',
        'glow-gold': '0 0 20px rgba(251, 191, 36, 0.6)',
        'glow-indigo': '0 0 20px rgba(67, 56, 202, 0.6)',
        // Legacy cyber glows for compatibility
        'glow-purple': '0 0 20px rgba(147, 51, 234, 0.5)',
        'glow-blue': '0 0 20px rgba(59, 130, 246, 0.5)',
        'glow-pink': '0 0 20px rgba(236, 72, 153, 0.5)',
        'glow-green': '0 0 20px rgba(16, 185, 129, 0.5)',
      },
      keyframes: {
        'katana-slash': {
          '0%': { transform: 'translateX(-100px) rotate(-45deg)', opacity: '0' },
          '50%': { transform: 'translateX(0) rotate(0deg)', opacity: '1' },
          '100%': { transform: 'translateX(100px) rotate(45deg)', opacity: '0' },
        },
        'cherry-blossom': {
          '0%': { transform: 'translateY(0) rotate(0deg)', opacity: '1' },
          '100%': { transform: 'translateY(20px) rotate(180deg)', opacity: '0' },
        },
      },
    },
  },
  plugins: [],
};
