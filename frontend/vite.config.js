import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    // `ws: true` proxies the /api/ws/analyses live-progress WebSocket too.
    proxy: { "/api": { target: "http://localhost:8000", ws: true } },
  },
});
