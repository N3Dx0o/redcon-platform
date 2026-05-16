import type { Config } from "tailwindcss";

export default {
  content: ["./src/**/*.{js,ts,jsx,tsx,mdx}"],
  theme: {
    extend: {
      colors: {
        bg: {
          dark: "#0a0a0f",
          sidebar: "#111118",
          main: "#16161f",
          card: "#1c1c28",
          elevated: "#22222e",
          hover: "#2a2a38",
        },
        border: {
          DEFAULT: "#2a2a3a",
          light: "#3a3a4a",
        },
        text: {
          primary: "#ffffff",
          secondary: "#a0a0b0",
          muted: "#6a6a7a",
        },
        redcon: {
          primary: "#c9353f",
          bright: "#e84855",
        },
        blue: {
          primary: "#3b82f6",
        },
        green: {
          primary: "#22c55e",
        },
        yellow: {
          primary: "#eab308",
        },
      },
    },
  },
  plugins: [],
} satisfies Config;




