const fs = require("node:fs");
const path = require("node:path");

const configuredUrl = (process.env.MAILGUARD_API_BASE_URL || "").trim();

if (!configuredUrl) {
  throw new Error(
    "Set MAILGUARD_API_BASE_URL to the HTTPS origin of your Vercel API."
  );
}

let parsedUrl;
try {
  parsedUrl = new URL(configuredUrl);
} catch {
  throw new Error("MAILGUARD_API_BASE_URL must be a valid HTTPS origin.");
}

if (
  parsedUrl.protocol !== "https:" ||
  !parsedUrl.hostname ||
  parsedUrl.pathname !== "/" ||
  parsedUrl.search ||
  parsedUrl.hash ||
  parsedUrl.username ||
  parsedUrl.password
) {
  throw new Error(
    "MAILGUARD_API_BASE_URL must be an HTTPS origin without credentials, path, query, or hash."
  );
}

const apiBaseUrl = parsedUrl.origin;
const configPath = path.join(__dirname, "..", "frontend", "api-config.js");
fs.writeFileSync(
  configPath,
  `window.MAILGUARD_API_BASE_URL = ${JSON.stringify(apiBaseUrl)};\n`
);
console.log(`Configured frontend API: ${apiBaseUrl}`);
