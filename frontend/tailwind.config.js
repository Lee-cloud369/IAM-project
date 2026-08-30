/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        "surface": "#111508",
        "surface-dim": "#111508",
        "surface-bright": "#373b2c",
        "surface-container-lowest": "#0c0f04",
        "surface-container-low": "#191d10",
        "surface-container": "#1d2113",
        "surface-container-high": "#282c1d",
        "surface-container-highest": "#333627",
        "surface-variant": "#333627",
        "surface-tint": "#a6d700",

        "background": "#111508",
        "on-background": "#e1e4cf",
        "on-surface": "#e1e4cf",
        "on-surface-variant": "#c3caac",
        "inverse-surface": "#e1e4cf",
        "inverse-on-surface": "#2e3223",

        "outline": "#8d9479",
        "outline-variant": "#434933",

        // Primary: Neon Lime
        "primary": "#ffffff",
        "primary-fixed": "#bef500",
        "primary-fixed-dim": "#a6d700",
        "on-primary-fixed": "#151f00",
        "on-primary-fixed-variant": "#3a4d00",
        "primary-container": "#bef500",
        "on-primary": "#273500",
        "on-primary-container": "#536d00",
        "inverse-primary": "#4e6700",

        // Secondary: Neon Magenta / Hot Pink
        "secondary": "#ffb0cd",
        "secondary-container": "#e00088",
        "secondary-fixed": "#ffd9e4",
        "secondary-fixed-dim": "#ffb0cd",
        "on-secondary": "#640039",
        "on-secondary-container": "#fffbff",
        "on-secondary-fixed": "#3e0022",
        "on-secondary-fixed-variant": "#8c0053",
        "neon-pink": "#FF2E9F",
        "neon-lime": "#C6FF00",

        // Tertiary: Icy Cyan
        "tertiary": "#ffffff",
        "tertiary-container": "#d0e6f5",
        "tertiary-fixed": "#d0e6f5",
        "tertiary-fixed-dim": "#b4c9d9",
        "on-tertiary": "#1e333f",
        "on-tertiary-container": "#526775",
        "on-tertiary-fixed": "#071e29",
        "on-tertiary-fixed-variant": "#354956",

        // Error / Alert
        "error": "#ffb4ab",
        "error-container": "#93000a",
        "on-error": "#690005",
        "on-error-container": "#ffdad6",
      },
      fontFamily: {
        "display-hero": ["Syne", "sans-serif"],
        "headline-sm": ["Syne", "sans-serif"],
        "metric-lg": ["Bebas Neue", "sans-serif"],
        "metric-md": ["Bebas Neue", "sans-serif"],
        "label-caps": ["Oswald", "sans-serif"],
        "body-md": ["Poppins", "Fira Sans", "sans-serif"],
        "mono": ["Fira Code", "monospace"],
      },
      fontSize: {
        "display-hero": ["48px", { lineHeight: "1.1", letterSpacing: "-0.02em", fontWeight: "800" }],
        "metric-lg": ["64px", { lineHeight: "1.0", letterSpacing: "0.05em", fontWeight: "400" }],
        "metric-md": ["32px", { lineHeight: "1.0", fontWeight: "400" }],
        "headline-sm": ["20px", { lineHeight: "1.4", fontWeight: "700" }],
        "body-md": ["16px", { lineHeight: "1.6", fontWeight: "400" }],
        "label-caps": ["12px", { lineHeight: "1.0", letterSpacing: "0.1em", fontWeight: "500" }],
      },
      spacing: {
        "unit": "4px",
        "gutter": "24px",
        "margin-mobile": "16px",
        "margin-desktop": "32px",
        "container-max": "1800px",
      },
      borderRadius: {
        "DEFAULT": "0.25rem",
        "lg": "0.5rem",
        "xl": "0.75rem",
        "full": "9999px",
      },
    },
  },
  plugins: [],
};
