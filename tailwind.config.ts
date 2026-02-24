import type { Config } from "tailwindcss";

export default {
  darkMode: 'class',  // ← added this line
  content: ["./src/**/*.{html,js,svelte,ts}"],

  theme: {
    extend: {
      colors: {
        accent: {
          DEFAULT: '#ff9f8a',
          start: '#ffce9d',
          end: '#ff839b',
        }
      }
    }
  },

  plugins: []
} as Config;