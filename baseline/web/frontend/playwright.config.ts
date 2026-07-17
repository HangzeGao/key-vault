import { defineConfig, devices } from "@playwright/test";

export default defineConfig({ testDir: "./e2e", use: { baseURL: "http://127.0.0.1:5173", screenshot: "only-on-failure", channel: "msedge" }, webServer: { command: "npm.cmd run dev -- --host 127.0.0.1", url: "http://127.0.0.1:5173/ui/login", reuseExistingServer: true }, projects: [{ name: "desktop", use: { ...devices["Desktop Chrome"] } }, { name: "narrow", use: { viewport: { width: 390, height: 844 } } }] });
