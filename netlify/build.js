const fs = require("node:fs");
const path = require("node:path");

const defaultApiUrl = "https://detect-phishing-mail.vercel.app";
const configuredUrl = (process.env.MAILGUARD_API_BASE_URL || defaultApiUrl).trim();

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
const frontendDir = path.join(__dirname, "..", "frontend");
fs.writeFileSync(
  path.join(frontendDir, "api-config.js"),
  'window.MAILGUARD_API_BASE_URL = "/api";\n'
);
fs.writeFileSync(
  path.join(frontendDir, "_redirects"),
  `/api/* ${apiBaseUrl}/:splat 200\n`
);
console.log(`Configured same-origin API proxy to: ${apiBaseUrl}`);
