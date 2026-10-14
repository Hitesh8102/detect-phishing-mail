const urgentTerms = [
  "urgent", "immediately", "action required", "final warning",
  "account suspended", "will be suspended", "within 24 hours",
  "verify now", "unusual activity", "limited time",
];
const credentialTerms = [
  "password", "login", "sign in", "verify your account",
  "confirm your identity", "one-time password", "otp",
  "bank details", "credit card", "social security",
];
const paymentTerms = [
  "wire transfer", "gift card", "payment overdue",
  "invoice attached", "change bank details", "send money",
];
const urlShorteners = new Set([
  "bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly",
  "shorturl.at", "ow.ly", "rb.gy",
]);
const suspiciousTlds = [".zip", ".mov", ".top", ".click", ".work", ".country"];

function addFinding(findings, label, detail, points) {
  findings.push({ label, detail, points });
}

function analyzeUrl(rawUrl, findings) {
  const value = rawUrl.trim();
  if (!value) return 0;

  let parsed;
  try {
    parsed = new URL(value.includes("://") ? value : `http://${value}`);
  } catch {
    parsed = null;
  }

  const host = parsed?.hostname.toLowerCase().replace(/\.$/, "") ?? "";
  let score = 0;
  if (!host || !host.includes(".")) {
    addFinding(findings, "Malformed URL", `Could not parse URL: ${value.slice(0, 120)}`, 2);
    return 2;
  }

  if (parsed.protocol.toLowerCase() !== "https:") {
    score += 1;
    addFinding(findings, "Non-HTTPS link", `${host} does not use HTTPS. This alone does not prove phishing.`, 1);
  }
  if (urlShorteners.has(host)) {
    score += 2;
    addFinding(findings, "URL shortener", `${host} hides the final destination.`, 2);
  }
  if (parsed.host.includes("@")) {
    score += 3;
    addFinding(findings, "URL contains @", "The URL authority contains '@', which can obscure the actual host.", 3);
  }
  if (host.startsWith("xn--") || host.includes(".xn--")) {
    score += 2;
    addFinding(findings, "Punycode domain", `${host} may use an internationalized domain that deserves closer inspection.`, 2);
  }
  if (suspiciousTlds.some((tld) => host.endsWith(tld))) {
    score += 1;
    addFinding(findings, "Uncommon top-level domain", `${host} uses a TLD sometimes seen in suspicious links; this is not proof of abuse.`, 1);
  }
  if (/\d{5,}/.test(host)) {
    score += 1;
    addFinding(findings, "Numbers in domain", `${host} contains a long sequence of digits.`, 1);
  }
  return score;
}

function analyzeEmail(payload) {
  const text = `${payload.subject}\n${payload.body}`.toLowerCase();
  const sender = payload.sender.trim();
  const findings = [];
  let score = 0;

  const urgentHits = urgentTerms.filter((term) => text.includes(term));
  if (urgentHits.length) {
    const points = Math.min(3, urgentHits.length);
    score += points;
    addFinding(findings, "Urgency or threat language", `Found wording such as: ${urgentHits.slice(0, 4).join(", ")}`, points);
  }

  const credentialHits = credentialTerms.filter((term) => text.includes(term));
  if (credentialHits.length) {
    const points = Math.min(4, credentialHits.length * 2);
    score += points;
    addFinding(findings, "Credential or sensitive-data request", `Found references to: ${credentialHits.slice(0, 5).join(", ")}`, points);
  }

  const paymentHits = paymentTerms.filter((term) => text.includes(term));
  if (paymentHits.length) {
    const points = Math.min(3, paymentHits.length * 2);
    score += points;
    addFinding(findings, "Payment or money request", `Found references to: ${paymentHits.slice(0, 4).join(", ")}`, points);
  }

  if (sender) {
    if (!sender.includes("@") || sender.startsWith("@") || sender.endsWith("@")) {
      score += 2;
      addFinding(findings, "Unusual sender format", "The sender address does not look like a standard email address.", 2);
    } else if (/\d{4,}/.test(sender.split("@").at(-1))) {
      score += 1;
      addFinding(findings, "Numbers in sender domain", "The sender domain contains a long sequence of digits; verify it independently.", 1);
    }
  }

  for (const url of payload.urls) score += analyzeUrl(url, findings);
  score = Math.min(score, 100);

  let risk;
  let summary;
  if (score >= 7) {
    risk = "High";
    summary = "Several warning signs were detected. Do not click links or provide information until verified independently.";
  } else if (score >= 3) {
    risk = "Medium";
    summary = "Some warning signs were detected. Verify the sender and destination through a trusted channel.";
  } else {
    risk = "Low";
    summary = "Few warning signs were detected by these basic checks. This does not prove the email is safe.";
  }

  if (!findings.length) {
    findings.push({
      label: "No obvious heuristic flags",
      detail: "The current rules did not find common warning patterns. More advanced phishing can still evade these checks.",
      points: 0,
    });
  }

  return {
    risk_level: risk,
    score,
    summary,
    findings,
    disclaimer: "Heuristic demo only; not a security verdict. The server does not visit submitted URLs.",
  };
}

function response(statusCode, body) {
  return {
    statusCode,
    headers: { "Content-Type": "application/json; charset=utf-8" },
    body: JSON.stringify(body),
  };
}

exports.handler = async (event) => {
  if (event.httpMethod !== "POST") {
    return response(405, { detail: "Method not allowed" });
  }

  let payload;
  try {
    payload = JSON.parse(event.body || "");
  } catch {
    return response(400, { detail: "Request body must be valid JSON." });
  }

  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    return response(422, { detail: "Request body must be a JSON object." });
  }

  const limits = { sender: 320, subject: 500, body: 20000 };
  for (const [field, maxLength] of Object.entries(limits)) {
    if (payload[field] !== undefined && typeof payload[field] !== "string") {
      return response(422, { detail: `${field} must be a string.` });
    }
    if ((payload[field] || "").length > maxLength) {
      return response(422, { detail: `${field} must be at most ${maxLength} characters.` });
    }
  }
  if (payload.urls !== undefined && (!Array.isArray(payload.urls) || payload.urls.length > 30 || payload.urls.some((url) => typeof url !== "string"))) {
    return response(422, { detail: "urls must be a list of at most 30 strings." });
  }

  return response(200, analyzeEmail({
    sender: payload.sender || "",
    subject: payload.subject || "",
    body: payload.body || "",
    urls: payload.urls || [],
  }));
};
