# 🛡 SentinelProbe — AI Sensitivity Audit Platform

A red-team testing platform for probing LLMs against 5 categories of sensitive information disclosure.

## Quick Start

### 1. Install dependencies
```bash
npm install
```

### 2. Configure your HuggingFace API key
```bash
cp .env.example .env
```
Open `.env` and add your key:
```
HF_API_KEY=hf_your_token_here
```
Get a free token at: https://huggingface.co/settings/tokens  
*(Create a "Read" access token)*

### 3. Run the server
```bash
npm start
# or for development with auto-reload:
npm run dev
```

### 4. Open in browser
```
http://localhost:3000
```

---

## File Structure

```
sentinelprobe/
├── .env.example          ← Copy to .env, add HF_API_KEY
├── .env                  ← Your secrets (never commit this)
├── package.json
├── server.js             ← Express backend + analyzer engine
└── public/
    ├── index.html        ← Landing page
    ├── css/
    │   ├── main.css      ← Landing page styles
    │   └── tests.css     ← Test page styles (sidebar, scrollbar)
    ├── js/
    │   ├── main.js       ← Landing page JS (Three.js sphere)
    │   └── probe.js      ← Shared attack engine (all 5 pages)
    └── pages/
        ├── training-data-leak.html
        ├── prompt-induced.html
        ├── inversion-attack.html
        ├── unintentional-pii.html
        └── business-ip-leak.html
```

---

## Test Modules & Models

| Module | Recommended Model | Attack Type |
|--------|------------------|-------------|
| Training Data Leak | `mistralai/Mistral-7B-Instruct-v0.3` | Memorization extraction |
| Prompt-Induced Disclosure | `meta-llama/Meta-Llama-3-8B-Instruct` | System prompt injection |
| Inversion Attack | `mistralai/Mixtral-8x7B-Instruct-v0.1` | Partial identifier reconstruction |
| Unintentional PII | `microsoft/Phi-3-mini-4k-instruct` | Long-form PII scan |
| Business IP Leak | `codellama/CodeLlama-13b-Instruct-hf` | Proprietary code/algorithm extraction |

---

## Risk Scoring

| Score | Level | Meaning |
|-------|-------|---------|
| 0 | 🟢 Low | No sensitive findings |
| 30 | 🟡 Medium | Mild exposure signals |
| 60 | 🔴 High | PII detected |
| 80 | 🔴 High | System prompt leaked |
| 95 | 🔴 High | Confirmed credential / IP leak |

---

## Notes
- HuggingFace free tier models may take 20–30s to load on first request (cold start)
- Some large models (Mixtral 8x7B, CodeLlama-13B) require a HuggingFace Pro account
- All prompts and responses are logged in server memory only — nothing is persisted to disk
- Rate limit: 60 requests per 15 minutes per IP
