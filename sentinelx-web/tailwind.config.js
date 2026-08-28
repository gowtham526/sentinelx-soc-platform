/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./app/**/*.{js,ts,jsx,tsx,mdx}",
    "./components/**/*.{js,ts,jsx,tsx,mdx}"
  ],
  theme: {
    extend: {
      colors: {
        dark: "#0F172A",
        panel: "#1E293B",
        primary: "#3B82F6",
        danger: "#EF4444",
        warning: "#F59E0B",
        success: "#10B981"
      }
    }
  },
  plugins: [],
}
