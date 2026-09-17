import React from 'react';

/**
 * The single QChat mark. Matches public/favicon.svg exactly, and is the only
 * logo used anywhere in the app — nav, auth screens, chat sidebar and footer.
 */
export default function Logo({ size = 32, className = '', withGlow = true }) {
  const radius = Math.round(size * 0.28);
  return (
    <span
      className={`inline-flex items-center justify-center flex-shrink-0 bg-gradient-to-br from-cyan-400 to-blue-500 ${withGlow ? 'shadow-glow-cyan-sm' : ''} ${className}`}
      style={{ width: size, height: size, borderRadius: radius }}
    >
      <svg
        viewBox="0 0 64 64"
        width={size * 0.6}
        height={size * 0.6}
        fill="none"
        aria-hidden="true"
      >
        <path
          d="M32 12 L48 19 V32 C48 41 41 48 32 52 C23 48 16 41 16 32 V19 Z"
          stroke="#030712"
          strokeWidth="4"
          strokeLinejoin="round"
        />
        <path d="M24 31 h16 v11 h-16 z" fill="#030712" />
        <path
          d="M27 31 v-4 a5 5 0 0 1 10 0 v4"
          stroke="#030712"
          strokeWidth="3.5"
          strokeLinecap="round"
        />
      </svg>
    </span>
  );
}
