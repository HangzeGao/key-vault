import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Build output goes to ../../internal/web/dist so Go can embed it via go:embed.
export default defineConfig({
  plugins: [react()],
  base: "/ui/",
  build: {
    outDir: "../../internal/web/dist",
    emptyOutDir: true,
    sourcemap: false,
    rollupOptions: {
      output: {
        // Stable hash-based filenames for long-term caching.
        chunkFileNames: "assets/[name]-[hash].js",
        entryFileNames: "assets/[name]-[hash].js",
        assetFileNames: "assets/[name]-[hash].[ext]",
      },
    },
  },
  server: {
    host: "0.0.0.0",
    port: 5173,
    proxy: {
      "/ui/api/v1": "http://localhost:8080",
      "/healthz": "http://localhost:8080",
    },
  },
});
