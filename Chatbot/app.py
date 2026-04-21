"""
CyberGuard AI - Cybersecurity Awareness Chatbot Backend
FastAPI server with Claude LLM integration and cybersecurity knowledge base
"""

import json
import os
import re
from pathlib import Path
from datetime import datetime

from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import anthropic
import uvicorn

# ── App Setup ──────────────────────────────────────────────────────────────────
app = FastAPI(title="CyberGuard AI", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static files
app.mount("/static", StaticFiles(directory="static"), name="static")

# ── Load Knowledge Base ────────────────────────────────────────────────────────
KB_PATH = Path("knowledge_base/cybersec_kb.json")
with open(KB_PATH) as f:
    KNOWLEDGE_BASE = json.load(f)

KB_SUMMARY = json.dumps(KNOWLEDGE_BASE, indent=2)

# ── Anthropic Client ───────────────────────────────────────────────────────────
client = anthropic.Anthropic(api_key=os.environ.get("ANTHROPIC_API_KEY", ""))

# ── System Prompt ──────────────────────────────────────────────────────────────
SYSTEM_PROMPT = f"""You are CyberGuard AI, an expert cybersecurity awareness assistant. Your mission is to educate users about cyber threats and help them stay safe online.

You have access to a comprehensive cybersecurity knowledge base:

{KB_SUMMARY}

## Your Capabilities:
1. **Threat Explanation**: Explain phishing, malware, ransomware, social engineering, MITM, SQL injection, DDoS, and more
2. **Link/Message Analysis**: Analyze URLs or messages for suspicious indicators
3. **Security Tips**: Provide actionable, step-by-step security advice
4. **Attack Examples**: Share real-world attack examples and case studies
5. **Incident Response**: Guide users through what to do if they've been attacked
6. **Password & MFA Guidance**: Help users with authentication best practices

## Response Style:
- Be clear, educational, and non-alarmist
- Use structured formatting with headers, bullet points, and emojis where appropriate
- Provide concrete, actionable advice
- When analyzing suspicious links/messages, be thorough and explain each red flag
- For complex topics, break them into digestible steps
- Always end security advice responses with a brief "Bottom Line" summary
- Use markdown formatting (headers with ##, bold with **, bullet points with -)

## Link/Message Analysis:
When a user shares a URL or message asking if it's suspicious:
1. Check for all suspicious indicators in the knowledge base
2. Rate the risk: 🟢 SAFE | 🟡 SUSPICIOUS | 🔴 DANGEROUS
3. Explain each red flag found
4. Recommend next steps

## Tone:
- Professional but approachable
- Empathetic — users may be scared or confused
- Proactive — always suggest what to do next
- Never make users feel stupid for falling for attacks

Stay focused on cybersecurity topics. If asked about unrelated topics, politely redirect to how you can help with security.
"""

# ── Pydantic Models ────────────────────────────────────────────────────────────
class ChatMessage(BaseModel):
    role: str
    content: str

class ChatRequest(BaseModel):
    message: str
    history: list[ChatMessage] = []

class LinkCheckRequest(BaseModel):
    url: str

class ChatResponse(BaseModel):
    response: str
    timestamp: str
    topic_detected: str | None = None

# ── Helper: Detect Topic ───────────────────────────────────────────────────────
def detect_topic(message: str) -> str | None:
    """Quick rule-based topic detection for UI hints."""
    msg = message.lower()
    topics = {
        "phishing": ["phish", "phishing", "fake email", "suspicious email"],
        "malware": ["malware", "virus", "trojan", "spyware", "keylogger"],
        "ransomware": ["ransomware", "ransom", "encrypted files", "pay bitcoin"],
        "password": ["password", "passphrase", "credential", "login"],
        "mfa": ["2fa", "mfa", "two factor", "authenticator", "multi-factor"],
        "link_check": ["is this link safe", "check this url", "suspicious link", "http://", "https://", "www."],
        "vpn": ["vpn", "public wifi", "wi-fi", "hotspot"],
        "backup": ["backup", "back up", "3-2-1", "restore"],
        "social_engineering": ["social engineering", "pretexting", "impersonation", "baiting"],
        "incident": ["hacked", "breach", "compromised", "infected", "attacked", "what do i do"],
    }
    for topic, keywords in topics.items():
        if any(kw in msg for kw in keywords):
            return topic
    return None

# ── Helper: Analyze URL Locally ────────────────────────────────────────────────
def pre_analyze_url(url: str) -> dict:
    """Quick rule-based URL pre-analysis before sending to LLM."""
    flags = []
    risk_score = 0

    # Check for IP address instead of domain
    if re.search(r'https?://\d+\.\d+\.\d+\.\d+', url):
        flags.append("Uses IP address instead of domain name")
        risk_score += 3

    # Check for URL shorteners
    shorteners = ["bit.ly", "tinyurl", "t.co", "goo.gl", "ow.ly", "short.io", "rb.gy", "cutt.ly"]
    if any(s in url.lower() for s in shorteners):
        flags.append("URL shortener detected — hides real destination")
        risk_score += 2

    # Check for @ symbol
    if "@" in url:
        flags.append("@ symbol in URL — browser ignores everything before it")
        risk_score += 3

    # Check for suspicious TLDs
    suspicious_tlds = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".work", ".click", ".loan"]
    if any(url.lower().endswith(tld) or f"{tld}/" in url.lower() for tld in suspicious_tlds):
        flags.append("Suspicious top-level domain (common in phishing/spam)")
        risk_score += 2

    # Check for HTTP (not HTTPS)
    if url.startswith("http://"):
        flags.append("Not using HTTPS — connection is not encrypted")
        risk_score += 1

    # Check for misspelled popular domains
    popular = {
        "paypal": ["paypa1", "paypall", "paypa-l", "pay-pal"],
        "google": ["go0gle", "googie", "g00gle"],
        "amazon": ["arnazon", "amaz0n", "amazzon"],
        "microsoft": ["micros0ft", "microsofl", "micosoft"],
        "apple": ["app1e", "appe", "aplle"],
        "facebook": ["faceb00k", "facebok", "faceboook"],
        "netflix": ["netfl1x", "netfliix", "netflixx"],
    }
    for brand, fakes in popular.items():
        if any(fake in url.lower() for fake in fakes):
            flags.append(f"Possible {brand} impersonation — domain looks like a typosquat")
            risk_score += 4

    # Excessive subdomains
    domain_part = re.sub(r'https?://', '', url).split('/')[0]
    if domain_part.count('.') > 3:
        flags.append("Excessive subdomains — could be hiding the real domain")
        risk_score += 2

    return {"flags": flags, "risk_score": risk_score}

# ── Routes ─────────────────────────────────────────────────────────────────────
@app.get("/", response_class=HTMLResponse)
async def serve_ui():
    with open("templates/index.html") as f:
        return f.read()

@app.post("/api/chat", response_model=ChatResponse)
async def chat(request: ChatRequest):
    """Main chat endpoint — sends message to Claude with cybersecurity context."""
    try:
        # Build message history for Claude
        messages = []
        for msg in request.history[-10:]:  # Keep last 10 messages for context
            messages.append({"role": msg.role, "content": msg.content})
        
        # Add current message
        messages.append({"role": "user", "content": request.message})

        # URL pre-analysis injection
        url_pattern = re.search(r'https?://[^\s]+', request.message)
        if url_pattern:
            url = url_pattern.group()
            pre_analysis = pre_analyze_url(url)
            if pre_analysis["flags"]:
                flags_text = "\n".join(f"- {f}" for f in pre_analysis["flags"])
                messages[-1]["content"] += f"\n\n[SYSTEM PRE-ANALYSIS: The following suspicious indicators were automatically detected in the URL:\n{flags_text}\nRisk score: {pre_analysis['risk_score']}/10. Please incorporate these findings in your analysis.]"

        response = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=1500,
            system=SYSTEM_PROMPT,
            messages=messages,
        )

        reply = response.content[0].text
        topic = detect_topic(request.message)

        return ChatResponse(
            response=reply,
            timestamp=datetime.utcnow().isoformat(),
            topic_detected=topic,
        )

    except anthropic.AuthenticationError:
        raise HTTPException(status_code=401, detail="Invalid API key. Please check your ANTHROPIC_API_KEY environment variable.")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error: {str(e)}")

@app.get("/api/quick-tips")
async def get_quick_tips():
    """Return quick security tips from the knowledge base."""
    return {"tips": KNOWLEDGE_BASE["quick_tips"]}

@app.get("/api/topics")
async def get_topics():
    """Return list of cybersecurity topics covered."""
    return {
        "threats": list(KNOWLEDGE_BASE["threats"].keys()),
        "best_practices": list(KNOWLEDGE_BASE["best_practices"].keys()),
    }

@app.get("/api/health")
async def health():
    return {"status": "online", "model": "claude-sonnet-4-20250514", "version": "1.0.0"}

# ── Entry Point ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        print("⚠️  WARNING: ANTHROPIC_API_KEY not set. Set it before running.")
    else:
        print("✅ Anthropic API key loaded.")
    
    print("🛡️  Starting CyberGuard AI on http://localhost:8000")
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)
