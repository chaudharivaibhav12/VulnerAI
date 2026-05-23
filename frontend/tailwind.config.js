/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      fontFamily: {
        display: ['Orbitron', 'monospace'],
        mono: ['"IBM Plex Mono"', 'monospace'],
      },
      colors: {
        v: {
          bg:          '#070d16',
          surface:     '#0d1117',
          raised:      '#161b22',
          border:      '#1e2d3d',
          'border-hi': '#2d4a6a',
          amber:       '#f0a500',
          'amber-dim': 'rgba(240,165,0,0.12)',
          'amber-mid': 'rgba(240,165,0,0.22)',
          red:         '#ff4444',
          'red-dim':   'rgba(255,68,68,0.12)',
          green:       '#00ff88',
          'green-dim': 'rgba(0,255,136,0.1)',
          blue:        '#58a6ff',
          'blue-dim':  'rgba(88,166,255,0.1)',
          text:        '#c9d1d9',
          bright:      '#e6edf3',
          dim:         '#1e2d3d',
          'dim-text':  '#6e7681',
        }
      },
      animation: {
        'blink':         'blink 1s step-end infinite',
        'slide-up':      'slideUp 0.25s ease-out',
        'critical-glow': 'criticalGlow 2s ease-in-out infinite',
        'amber-glow':    'amberGlow 2.5s ease-in-out infinite',
        'fade-in':       'fadeIn 0.3s ease-out',
        'dot-pulse':     'dotPulse 1.5s ease-in-out infinite',
      },
      keyframes: {
        blink:       { '0%,100%': { opacity: 1 }, '50%': { opacity: 0 } },
        slideUp:     { from: { opacity: 0, transform: 'translateY(8px)' }, to: { opacity: 1, transform: 'translateY(0)' } },
        fadeIn:      { from: { opacity: 0 }, to: { opacity: 1 } },
        dotPulse:    { '0%,100%': { opacity: 1 }, '50%': { opacity: 0.4 } },
        criticalGlow: {
          '0%,100%': { boxShadow: '0 0 8px rgba(255,68,68,0.4), inset 0 0 8px rgba(255,68,68,0.06)' },
          '50%':     { boxShadow: '0 0 28px rgba(255,68,68,0.7), 0 0 56px rgba(255,68,68,0.2), inset 0 0 14px rgba(255,68,68,0.1)' },
        },
        amberGlow: {
          '0%,100%': { boxShadow: '0 0 6px rgba(240,165,0,0.3)' },
          '50%':     { boxShadow: '0 0 20px rgba(240,165,0,0.6), 0 0 40px rgba(240,165,0,0.15)' },
        },
      }
    },
  },
  plugins: [],
}
