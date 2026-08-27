export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        navy: { 900: '#0a0e1a', 800: '#111827', 700: '#1a2332', 600: '#243044' },
        cyan: { 400: '#22d3ee', 500: '#06b6d4', 600: '#0891b2' },
        threat: { red: '#ef4444', orange: '#f97316', yellow: '#eab308' },
        safe: { green: '#22c55e' },
      },
      fontFamily: {
        mono: ['JetBrains Mono', 'monospace'],
        sans: ['Inter', 'system-ui', 'sans-serif'],
      },
    },
  },
  plugins: [],
}
