import type { Config } from "tailwindcss";

export default {
  darkMode: 'class',
  content: ["./src/**/*.{html,js,svelte,ts}"],

  theme: {
    extend: {
      colors: {
        accent: {
          DEFAULT: '#ff9f8a',
          start: '#ffce9d',
          end: '#ff839b',
        }
      },
      borderRadius: {
        DEFAULT: '0px',
        sm: '0px',
        md: '0px',
        lg: '0px',
        xl: '0px',
        '2xl': '0px',
        '3xl': '0px',
        full: '0px',
      },
      fontFamily: {
        mono: ['"JetBrains Mono"', 'monospace'],
        sans: ['Inter', 'system-ui', '-apple-system', 'sans-serif'],
      }
    }
  },

  plugins: []
} as Config;