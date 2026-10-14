import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig(({ command }) => {
  if (command === "build" && !process.env["VITE_API_URL"]) throw new Error("VITE_API_URL is required for a production build");
  return config;
});

const config = defineConfig({
  plugins: [react()],
  server: { port: Number(process.env.PORT ?? 5174), proxy: { "/api": process.env.API_PROXY ?? "http://localhost:8080" } },
  build: { sourcemap: false },
});
