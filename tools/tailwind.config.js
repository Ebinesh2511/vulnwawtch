/** Build: cd tools && npm run css   (or npm run css:watch while editing templates) */
module.exports = {
  darkMode: "class",
  content: ["../app/templates/**/*.html", "../app/static/vw.js"],
  // built in JS as "sev-" + severity, so Tailwind cannot see them in the source
  safelist: ["sev-CRITICAL", "sev-KEV", "sev-HIGH", "sev-MODERATE", "sev-MEDIUM", "sev-LOW", "sev-UNKNOWN", "sev-"],
  theme: {
    extend: {
      fontFamily: {
        sans: ["Inter", "ui-sans-serif", "system-ui", "-apple-system", "Segoe UI", "sans-serif"],
        mono: ["JetBrains Mono", "ui-monospace", "SFMono-Regular", "Menlo", "monospace"],
      },
      transitionTimingFunction: { out: "cubic-bezier(.2,.8,.2,1)" },
    },
  },
  plugins: [require("@tailwindcss/forms")({ strategy: "class" })],
};
