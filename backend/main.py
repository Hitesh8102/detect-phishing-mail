from typing import List
from urllib.parse import urlparse
import re

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

app = FastAPI(
    title="Phishing Email Detector API",
    description="A beginner-friendly heuristic email risk analyzer. Not a guarantee of safety.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)

class AnalyzeRequest(BaseModel):
    sender: str = Field(default="", max_length=320)
    subject: str = Field(default="", max_length=500)
    body: str = Field(default="", max_length=20000)
    urls: List[str] = Field(default_factory=list, max_length=30)

class Finding(BaseModel):
    label: str
    detail: str
    points: int

class AnalyzeResponse(BaseModel):
    risk_level: str
    score: int
    summary: str
    findings: List[Finding]
    disclaimer: str

URGENT_TERMS = [
    "urgent", "immediately", "action required", "final warning",
    "account suspended", "will be suspended", "within 24 hours",
    "verify now", "unusual activity", "limited time",
]
CREDENTIAL_TERMS = [
    "password", "login", "sign in", "verify your account",
    "confirm your identity", "one-time password", "otp",
    "bank details", "credit card", "social security",
]
PAYMENT_TERMS = [
    "wire transfer", "gift card", "payment overdue",
    "invoice attached", "change bank details", "send money",
]
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly",
    "shorturl.at", "ow.ly", "rb.gy",
}
SUSPICIOUS_TLDS = {".zip", ".mov", ".top", ".click", ".work", ".country"}

def add_finding(findings: list, label: str, detail: str, points: int):
    findings.append(Finding(label=label, detail=detail, points=points))

def analyze_url(raw_url: str, findings: list) -> int:
    value = raw_url.strip()
    if not value:
        return 0
    candidate = value if "://" in value else "http://" + value
    try:
        parsed = urlparse(candidate)
        host = (parsed.hostname or "").lower().rstrip(".")
    except ValueError:
        host = ""

    score = 0
    if not host or "." not in host:
        add_finding(findings, "Malformed URL", f"Could not parse URL: {value[:120]}", 2)
        return 2

    if parsed.scheme.lower() != "https":
        score += 1
        add_finding(findings, "Non-HTTPS link", f"{host} does not use HTTPS. This alone does not prove phishing.", 1)

    if host in URL_SHORTENERS:
        score += 2
        add_finding(findings, "URL shortener", f"{host} hides the final destination.", 2)

    if "@" in parsed.netloc:
        score += 3
        add_finding(findings, "URL contains @", "The URL authority contains '@', which can obscure the actual host.", 3)

    if host.startswith("xn--") or ".xn--" in host:
        score += 2
        add_finding(findings, "Punycode domain", f"{host} may use an internationalized domain that deserves closer inspection.", 2)

    if any(host.endswith(tld) for tld in SUSPICIOUS_TLDS):
        score += 1
        add_finding(findings, "Uncommon top-level domain", f"{host} uses a TLD sometimes seen in suspicious links; this is not proof of abuse.", 1)

    if re.search(r"\d{5,}", host):
        score += 1
        add_finding(findings, "Numbers in domain", f"{host} contains a long sequence of digits.", 1)

    return score

@app.get("/")
def root():
    return {"message": "Phishing Email Detector API is running", "docs": "/docs"}

@app.get("/health")
def health():
    return {"status": "ok"}

@app.post("/analyze", response_model=AnalyzeResponse)
def analyze_email(payload: AnalyzeRequest):
    text = f"{payload.subject}\n{payload.body}".lower()
    sender = payload.sender.strip()
    findings = []
    score = 0

    urgent_hits = [term for term in URGENT_TERMS if term in text]
    if urgent_hits:
        points = min(3, len(urgent_hits))
        score += points
        add_finding(findings, "Urgency or threat language",
                    "Found wording such as: " + ", ".join(urgent_hits[:4]), points)

    credential_hits = [term for term in CREDENTIAL_TERMS if term in text]
    if credential_hits:
        points = min(4, len(credential_hits) * 2)
        score += points
        add_finding(findings, "Credential or sensitive-data request",
                    "Found references to: " + ", ".join(credential_hits[:5]), points)

    payment_hits = [term for term in PAYMENT_TERMS if term in text]
    if payment_hits:
        points = min(3, len(payment_hits) * 2)
        score += points
        add_finding(findings, "Payment or money request",
                    "Found references to: " + ", ".join(payment_hits[:4]), points)

    if sender:
        if "@" not in sender or sender.startswith("@") or sender.endswith("@"):
            score += 2
            add_finding(findings, "Unusual sender format",
                        "The sender address does not look like a standard email address.", 2)
        elif re.search(r"\d{4,}", sender.split("@", 1)[-1]):
            score += 1
            add_finding(findings, "Numbers in sender domain",
                        "The sender domain contains a long sequence of digits; verify it independently.", 1)

    for url in payload.urls[:30]:
        score += analyze_url(url, findings)

    score = min(score, 100)
    if score >= 7:
        risk = "High"
        summary = "Several warning signs were detected. Do not click links or provide information until verified independently."
    elif score >= 3:
        risk = "Medium"
        summary = "Some warning signs were detected. Verify the sender and destination through a trusted channel."
    else:
        risk = "Low"
        summary = "Few warning signs were detected by these basic checks. This does not prove the email is safe."

    if not findings:
        findings.append(Finding(
            label="No obvious heuristic flags",
            detail="The current rules did not find common warning patterns. More advanced phishing can still evade these checks.",
            points=0,
        ))

    return AnalyzeResponse(
        risk_level=risk,
        score=score,
        summary=summary,
        findings=findings,
        disclaimer="Heuristic demo only; not a security verdict. The server does not visit submitted URLs.",
    )
