# 🛡️ CyberGuard AI — Cybersecurity Awareness Chatbot

An AI-powered cybersecurity education chatbot built with FastAPI + Claude AI, featuring a sleek terminal-inspired chat interface.

---

## 📁 Project Structure

```
cybersec-chatbot/
├── app.py                          # FastAPI backend (main server)
├── requirements.txt                # Python dependencies
├── knowledge_base/
│   └── cybersec_kb.json            # Comprehensive cybersecurity knowledge base
├── templates/
│   └── index.html                  # Chat UI (standalone, works without backend too)
└── static/
    ├── css/                        # Additional CSS (if extended)
    └── js/                         # Additional JS (if extended)
```

---

## 🚀 Quick Start

### Option A: Standalone HTML (No Backend Needed)

The `templates/index.html` file is fully self-contained and calls the Anthropic API directly from the browser.

1. Open `templates/index.html` in any modern browser
2. That's it — Claude AI powers the chatbot directly

> ⚠️ Note: This uses your Anthropic API key embedded in requests. For production, always use the backend to keep your API key secret.

---

### Option B: Full Backend Setup (Recommended for Production)

#### Prerequisites
- Python 3.11+
- An Anthropic API key → [Get one here](https://console.anthropic.com/)

#### Step 1: Clone & Navigate
```bash
cd cybersec-chatbot
```

#### Step 2: Create Virtual Environment
```bash
python -m venv venv

# Activate:
# macOS/Linux:
source venv/bin/activate
# Windows:
venv\Scripts\activate
```

#### Step 3: Install Dependencies
```bash
pip install -r requirements.txt
```

#### Step 4: Set API Key
```bash
# macOS/Linux:
export ANTHROPIC_API_KEY="sk-ant-your-key-here"

# Windows (Command Prompt):
set ANTHROPIC_API_KEY=sk-ant-your-key-here

# Windows (PowerShell):
$env:ANTHROPIC_API_KEY="sk-ant-your-key-here"
```

#### Step 5: Run the Server
```bash
python app.py
```

Or with uvicorn directly:
```bash
uvicorn app:app --host 0.0.0.0 --port 8000 --reload
```

#### Step 6: Open the Chatbot
Visit: **http://localhost:8000**

---

## 🌐 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/` | Chat UI |
| `POST` | `/api/chat` | Send message, get AI response |
| `GET` | `/api/quick-tips` | Get security quick tips |
| `GET` | `/api/topics` | List covered topics |
| `GET` | `/api/health` | Server health check |

### Example API Request
```bash
curl -X POST http://localhost:8000/api/chat \
  -H "Content-Type: application/json" \
  -d '{
    "message": "What is phishing and how do I recognize it?",
    "history": []
  }'
```

---

## 🎯 Features

### 🛡️ Cybersecurity Topics Covered
- **Phishing** — Types, indicators, real examples, prevention
- **Malware** — Viruses, trojans, spyware, ransomware, keyloggers
- **Ransomware** — How it works, famous attacks (WannaCry, Colonial Pipeline), response steps
- **Social Engineering** — Psychological manipulation techniques
- **Man-in-the-Middle Attacks** — SSL stripping, Wi-Fi eavesdropping
- **DDoS Attacks** — Types and mitigation
- **SQL Injection** — Examples and prevention
- **Password Security** — Best practices and password managers
- **Multi-Factor Authentication** — Setup guides
- **Network Security** — Wi-Fi, VPN, firewalls
- **Incident Response** — Step-by-step what to do if attacked

### 🔍 URL Analysis
Paste any URL and get:
- Automatic suspicious pattern detection
- Risk rating: 🟢 SAFE | 🟡 SUSPICIOUS | 🔴 DANGEROUS
- Explanation of each red flag
- Recommended next steps

### 💡 Quick Actions
- Predefined topic buttons in sidebar
- Quick pill buttons for common questions
- Starter cards for new users

### 📋 Chat Export
Export your entire conversation as a text file for reference.

---

## 🔒 Security Notes

1. **Never commit your API key** — use environment variables
2. **Rate limiting** — Add rate limiting for production deployments
3. **HTTPS** — Use SSL/TLS in production (e.g., with nginx)
4. **Input validation** — The backend validates all inputs via Pydantic

---

## 🛠️ Customization

### Adding to the Knowledge Base
Edit `knowledge_base/cybersec_kb.json` to add new threats, tips, or best practices. The JSON structure is self-documenting.

### Changing the AI Model
In `app.py`, update the model string:
```python
response = client.messages.create(
    model="claude-opus-4-5",  # More capable but slower
    # or
    model="claude-haiku-4-5-20251001",  # Faster, cheaper
    ...
)
```

### Deploying to Production

**Railway / Render / Fly.io:**
```bash
# Set environment variable ANTHROPIC_API_KEY in your platform dashboard
# Then deploy with:
railway up
# or
render deploy
```

**Docker:**
```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
EXPOSE 8000
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
```

---

## 📊 Knowledge Base Structure

```json
{
  "threats": {
    "phishing": { "definition", "types", "indicators", "examples", "prevention" },
    "malware": { "definition", "types", "infection_vectors", "prevention" },
    "ransomware": { "definition", "how_it_works", "famous_attacks", "prevention", "if_infected" },
    "social_engineering": { ... },
    "man_in_the_middle": { ... },
    "sql_injection": { ... },
    "ddos": { ... }
  },
  "best_practices": {
    "passwords": { "rules", "strong_examples" },
    "mfa": { "definition", "types", "best_options" },
    "backup_strategy": { "rule", "details" },
    "network_security": [ ... ],
    "email_security": [ ... ],
    "browsing_safety": [ ... ]
  },
  "link_analysis": { "suspicious_indicators", "how_to_check" },
  "incident_response": { "steps", "contacts" },
  "quick_tips": [ ... ]
}
```

---

## 📄 License

MIT License — Free to use, modify, and distribute.

---

## 🙏 Built With

- **[Anthropic Claude](https://www.anthropic.com)** — AI backbone
- **[FastAPI](https://fastapi.tiangolo.com)** — Python web framework
- **[JetBrains Mono](https://www.jetbrains.com/legalnotices/monofont/)** — Monospace font
- **[Syne](https://fonts.google.com/specimen/Syne)** — Display font
