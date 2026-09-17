/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        navy: {
          950: '#030712',
          900: '#060d1f',
          850: '#080f25',
          800: '#0b1530',
          700: '#0f1e44',
          600: '#162354',
        },
        cyan: {
          DEFAULT: '#00C8FF',
          dim: 'rgba(0,200,255,0.15)',
          glow: 'rgba(0,200,255,0.4)',
        },
        emerald: {
          quantum: '#00FFB2',
        },
        rose: {
          quantum: '#FF2D78',
        },
        violet: {
          quantum: '#8B5CF6',
        },
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'monospace'],
      },
      backdropBlur: {
        xs: '4px',
        '2xl': '40px',
      },
      boxShadow: {
        'glow-cyan': '0 0 20px rgba(0, 200, 255, 0.35)',
        'glow-cyan-sm': '0 0 10px rgba(0, 200, 255, 0.25)',
        'glow-green': '0 0 12px rgba(0, 255, 178, 0.4)',
        'glow-violet': '0 0 28px rgba(139, 92, 246, 0.28)',
        'glow-lift': '0 18px 50px -18px rgba(0, 200, 255, 0.35)',
      },
      keyframes: {
        drift: {
          '0%': { transform: 'translate(0, 0) scale(1)' },
          '33%': { transform: 'translate(40px, -30px) scale(1.05)' },
          '66%': { transform: 'translate(-20px, 50px) scale(0.97)' },
          '100%': { transform: 'translate(30px, 20px) scale(1.03)' },
        },
        'fade-up': {
          from: { opacity: '0', transform: 'translateY(12px)' },
          to:   { opacity: '1', transform: 'translateY(0)' },
        },
        shimmer: {
          '0%':   { backgroundPosition: '-200% center' },
          '100%': { backgroundPosition: '200% center' },
        },
        ping2: {
          '0%, 100%': { transform: 'scale(1)', opacity: '1' },
          '50%':       { transform: 'scale(1.5)', opacity: '0' },
        },
        'gradient-pan': {
          '0%, 100%': { backgroundPosition: '0% 50%' },
          '50%':      { backgroundPosition: '100% 50%' },
        },
        float: {
          '0%, 100%': { transform: 'translateY(0)' },
          '50%':      { transform: 'translateY(-10px)' },
        },
        'sheen': {
          '0%':   { transform: 'translateX(-120%) skewX(-18deg)' },
          '100%': { transform: 'translateX(220%) skewX(-18deg)' },
        },
      },
      animation: {
        drift:    'drift 18s ease-in-out infinite alternate',
        'drift-d':'drift 18s ease-in-out infinite alternate-reverse',
        'fade-up':'fade-up 0.35s ease both',
        shimmer:  'shimmer 2.5s linear infinite',
        'ping2':  'ping2 1.4s ease-in-out infinite',
        'gradient-pan': 'gradient-pan 7s ease infinite',
        float:    'float 6s ease-in-out infinite',
        sheen:    'sheen 2.4s ease-in-out infinite',
      },
    },
  },
  plugins: [],
}
