import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// `base` is configurable so one build works in every host:
//   - Vercel / Netlify / Cloudflare Pages   →  default "/"
//   - GitHub Pages project site             →  VITE_BASE=/Vigenere-Solver/
//   - Static file:// preview                →  VITE_BASE=./
export default defineConfig(() => ({
  base: process.env.VITE_BASE ?? "/",
  plugins: [react()],
  server: { host: "0.0.0.0", port: 5173 },
  preview: { host: "0.0.0.0", port: 4173 },
  build: {
    target: "es2020",
    sourcemap: false,
    chunkSizeWarningLimit: 800,
  },
}));
