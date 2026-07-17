/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        base: "#0a0a0e",
        surface: "#12121a",
        "surface-2": "#1a1a26",
        inset: "#070709",
        border: "#252533",
        "border-bright": "#3a3a4d",
        accent: "#f5a623",
        "accent-bright": "#ffb627",
        success: "#4ade80",
        warning: "#fbbf24",
        danger: "#f87171",
        info: "#60a5fa",
      },
      fontFamily: {
        display: ['"Major Mono Display"', "monospace"],
        mono: ['"JetBrains Mono"', "monospace"],
        sans: ['"Spline Sans"', "system-ui", "sans-serif"],
      },
    },
  },
  plugins: [],
};
