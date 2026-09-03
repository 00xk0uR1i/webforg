/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  safelist: [
    { pattern: /bg-(red|amber|green|blue|yellow|purple|cyan|gray|orange)-(900\/20|800\/50|800\/30|800|700|600|500|400\/20|400\/10|400)/ },
    { pattern: /border-(red|amber|green|blue|yellow|purple|cyan|gray|orange)-(800\/30|700|600|500)/ },
    { pattern: /text-(red|amber|green|blue|yellow|purple|cyan|gray|orange)-(400|500|600)/ },
    { pattern: /ring-(red|amber|green|blue|yellow|purple|cyan|orange|webforge)-500/ },
    { pattern: /from-(red|amber|green|blue|yellow|purple|cyan|gray|orange)-950/ },
    { pattern: /to-(gray-900|gray-800)/ },
  ],
  theme: {
    extend: {
      colors: {
        webforge: {
          50:  '#f0fdf4',
          100: '#dcfce7',
          200: '#bbf7d0',
          300: '#86efac',
          400: '#4ade80',
          500: '#22c55e',
          600: '#16a34a',
          700: '#15803d',
          800: '#166534',
          900: '#14532d',
          950: '#052e16',
        },
      },
      animation: {
        'fade-in': 'fadeIn 0.2s ease-out',
        'slide-up': 'slideUp 0.25s ease-out',
        'slide-in-right': 'slideInRight 0.2s ease-out',
      },
      keyframes: {
        fadeIn: {
          '0%': { opacity: '0' },
          '100%': { opacity: '1' },
        },
        slideUp: {
          '0%': { opacity: '0', transform: 'translateY(8px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
        slideInRight: {
          '0%': { opacity: '0', transform: 'translateX(8px)' },
          '100%': { opacity: '1', transform: 'translateX(0)' },
        },
      },
    },
  },
  plugins: [],
}
