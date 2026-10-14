import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: { port: Number(process.env.PORT ?? 5174), proxy: { "/api": process.env.API_PROXY ?? "http://localhost:8080" } },
  build: { sourcemap: false },
});
