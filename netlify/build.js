const fs = require("node:fs");
const path = require("node:path");

const configuredUrl = (process.env.PHISHGUARD_API_BASE_URL || "").trim();
let apiBaseUrl = "";

if (configuredUrl) {
  let parsedUrl;
  try {
    parsedUrl = new URL(configuredUrl);
  } catch {
    throw new Error("PHISHGUARD_API_BASE_URL must be a valid HTTPS origin.");
  }

  if (
    parsedUrl.protocol !== "https:" ||
    parsedUrl.pathname !== "/" ||
    parsedUrl.search ||
    parsedUrl.hash
  ) {
    throw new Error(
      "PHISHGUARD_API_BASE_URL must be an HTTPS origin without a path, query, or hash."
    );
  }

  apiBaseUrl = parsedUrl.origin;
}

const configPath = path.join(__dirname, "..", "frontend", "api-config.js");
fs.writeFileSync(
  configPath,
  `window.PHISHGUARD_API_BASE_URL = ${JSON.stringify(apiBaseUrl)};\n`
);
console.log(
  apiBaseUrl
    ? `Configured frontend API: ${apiBaseUrl}`
    : "No Vercel API URL configured; using the Netlify Function fallback."
);
