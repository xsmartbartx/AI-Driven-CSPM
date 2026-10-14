import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig(({ command }) => {
  // a production bundle without these would ship localhost links and call its own origin for the API
  if (command === "build") for (const k of ["VITE_APP_URL", "VITE_API_URL"]) if (!process.env[k]) throw new Error(`${k} is required for a production build`);
  return config;
});

const config = defineConfig({
  plugins: [react()],
  server: { port: Number(process.env.PORT ?? 5173), proxy: { "/api": process.env.API_PROXY ?? "http://localhost:8080" } },
});
