# MailGuard Phishing Risk Analyzer

Production deployment uses a static frontend on Netlify and a Python FastAPI API on Vercel. Email scans use Claude when `ANTHROPIC_API_KEY` is configured and clearly identified local heuristics otherwise. Website URLs are assessed locally by URL-pattern heuristics. Results can be wrong and are not a security verdict.

## Features
- Paste email sender, subject, body, and optional URLs
- Submit a website URL for an immediate URL-only heuristic check; it does not require an Anthropic API key
- Email checks keep working without an Anthropic API key using local checks for credential requests, urgency, suspicious payments, brand impersonation, malware lures, and suspicious links
- Supports review of common phishing and social-engineering signals; it cannot guarantee detection of every phishing attempt
- Gives every risk assessment a score out of 10 with a visual guide: Low 0–3, Medium 4–6, High 7–10
- Shows the likely phishing type, such as credential theft, impersonation, invoice fraud, or malware delivery; if the evidence is unclear, it says so
- No email is sent from your account and no mailbox access is performed
- Submitted email content is sent to Anthropic only when its backend API key is configured; otherwise email checks run locally. Do not submit confidential or personal emails.
- Website URL checks run in the backend using URL text only; URLs are not sent to Anthropic or fetched.

## Deploy the API to Vercel

1. Import this repository into Vercel and set the project's **Root Directory** to `backend`.
2. Use the FastAPI framework preset or automatic detection; keep the default build settings.
3. `FRONTEND_ORIGINS` is optional when using the Netlify proxy; the browser calls Netlify and Netlify forwards API requests to Vercel. If you use the API directly from another browser frontend, set this variable to that frontend's exact HTTPS origin(s), comma-separated. Never use `*`.
4. Add `ANTHROPIC_API_KEY` as a Vercel environment variable for AI email analysis. Keep it in Vercel only—never add it to Netlify, frontend code, or this repository. Without the key, email scans use the limited local checks.
5. Optionally set `ANTHROPIC_MODEL` to a model enabled for your account.
6. Deploy. Vercel detects `main.py`, `.python-version`, and `requirements.txt`.
7. Verify `https://<your-vercel-project>.vercel.app/health` reports `"status":"ok"`.

## Deploy the frontend to Netlify

1. Import the same repository into Netlify and set the base directory to the repository root.
2. Deploy. The frontend uses a same-origin Netlify proxy to forward `/api/*` requests to `https://detect-phishing-mail.vercel.app`; no Netlify environment variable is required for the configured API. If you change the Vercel project URL, set `MAILGUARD_API_BASE_URL` in Netlify to its HTTPS origin and redeploy.
3. Test both sample scans on the deployed Netlify site. Because requests use the Netlify proxy, browser CORS configuration is not required for this frontend.

The production frontend has no localhost or `file://` API fallback. The Netlify proxy keeps browser requests same-origin and forwards them to the configured Vercel API.

## API

`POST /analyze` accepts email fields: `sender`, `subject`, `body`, and optional `urls`.

`POST /analyze-website` accepts a URL:

```json
{
  "url": "https://example.com/login"
}
```

Email example:

```json
{
  "sender": "security@example.com",
  "subject": "Urgent: verify your account",
  "body": "Your account will be suspended. Click the link and enter your password.",
  "urls": ["http://example-login-security.test/verify"]
}
```

Responses include `phishing_type` and an integer score from 0 to 10: Low is 0–3, Medium is 4–6, and High is 7–10. The risk level is aligned with the score.

## Production security and limitations
- CORS permits only the exact HTTPS origins listed in Vercel's `FRONTEND_ORIGINS`; responses include no-store, HSTS, and security headers.
- CORS is a browser control, not authentication. The API endpoints are public and can still be called outside a browser; enable Vercel Firewall/rate limits before broad public use.
- Email text is sent to Anthropic only when `ANTHROPIC_API_KEY` is configured. Otherwise the API uses limited local heuristic checks. Do not submit confidential, personal, or regulated information.
- Website checks evaluate only visible URL patterns. They do not visit websites, inspect page content, or check live reputation.
- AI and heuristic assessments can be wrong and cannot guarantee detection of every phishing attempt. This educational demo does not replace your organization's security tools.
#
