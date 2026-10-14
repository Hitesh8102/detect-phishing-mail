# Phishing Email Detector (Beginner Full-Stack Project)

A responsive HTML/CSS/JavaScript frontend with a Netlify Function and an optional Python FastAPI API.
Both analyzers use transparent heuristic checks; neither is a trained machine-learning model or can guarantee an email is safe.

## Features
- Paste email sender, subject, body, and optional URLs
- Analyzes urgency language, credential/payment requests, sender mismatches, and suspicious URL patterns
- Risk result: Low / Medium / High, with reasons
- No email is sent and no mailbox access is performed

## Deploy the backend to Vercel

The FastAPI backend is deployed separately from the Netlify frontend.

1. Import this repository into Vercel.
2. Set the Vercel project's **Root Directory** to `backend`.
3. Leave the framework preset on **FastAPI** (or automatic detection), and leave the build and output directory settings at their defaults.
4. Deploy. Vercel detects `main.py`, `.python-version`, and `requirements.txt`.
5. Verify `https://<your-vercel-project>.vercel.app/health` returns `{"status":"ok"}`. The interactive API documentation is at `/docs`.

## Deploy and connect the frontend on Netlify

1. Import the same repository into Netlify and keep the base directory at the repository root.
2. In the Netlify site's environment variables, add `PHISHGUARD_API_BASE_URL` with your Vercel project URL, for example `https://your-project.vercel.app` (no `/analyze` suffix).
3. Deploy. `netlify.toml` builds the frontend and deploys a Netlify Function fallback; the frontend calls the Vercel `/analyze` endpoint when the environment variable is set.

The API allows cross-origin requests because it is a public demo with no credentials or user-specific data. The endpoint does not store email contents. The Netlify Function is used as a fallback when `PHISHGUARD_API_BASE_URL` is unset.

For local Netlify testing, install Node.js and run `npx netlify-cli dev` from the repository root. Open the local URL it prints (normally `http://localhost:8888`).

## Run the backend locally

Open a terminal in the `backend` folder:

```bash
python -m venv .venv
# Windows:
.venv\\Scripts\\activate
# macOS/Linux:
source .venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --reload
```

API runs at `http://127.0.0.1:8000`. Interactive API docs: `http://127.0.0.1:8000/docs`.

## Run a local static preview

Start the FastAPI backend first. Then run a static server from the project root:

```bash
python -m http.server 5500
```

Then open `http://127.0.0.1:5500/frontend/`. The page uses the local FastAPI backend on this preview. Alternatively, open `frontend/index.html` directly if your browser permits requests from `file://`.

The backend allows cross-origin requests for the same reason as the deployed public demo API.

## API
`POST /analyze`

Example JSON:
```json
{
  "sender": "security@example.com",
  "subject": "Urgent: verify your account",
  "body": "Your account will be suspended. Click the link and enter your password.",
  "urls": ["http://example-login-security.test/verify"]
}
```

## Important limitations and safety
- Heuristics can produce false positives and false negatives.
- Do not paste confidential, personal, or regulated information into a demo.
- URL checks are pattern-based; the server does not visit URLs.
- Do not automatically open detected links.
- For a production version, add a labeled dataset, model evaluation, authentication/rate limits, logging/privacy controls, and threat-intelligence integrations.
