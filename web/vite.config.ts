import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

// The built SPA is embedded into the Go binary (see embed.go) and served by
// the admin listener. In development `npm run dev` proxies the API to a
// locally running gatekeeper so cookies stay same-origin.
export default defineConfig({
  plugins: [react(), tailwindcss()],
  build: {
    outDir: "dist",
    emptyOutDir: true,
    chunkSizeWarningLimit: 900,
  },
  server: {
    port: 5173,
    proxy: {
      "/api": { target: "http://127.0.0.1:9090", changeOrigin: false },
      "/healthz": { target: "http://127.0.0.1:9090" },
      "/ca.crt": { target: "http://127.0.0.1:9090" },
    },
  },
  test: {
    environment: "jsdom",
    setupFiles: ["./test/setup.ts"],
    globals: true,
    css: false,
  },
});
