# 🛡 SentinelProbe

**AI Security Audit Platform** — Test language models for data leakage, prompt injection, PII exposure, and intellectual property risks.

🔗 **Live Demo:** [https://sentinelprobe.vercel.app](https://sentinelprobe.vercel.app)

---

## What is SentinelProbe?

SentinelProbe is a red-teaming tool for AI systems. It lets you probe large language models with crafted attack prompts and automatically analyzes responses for security risks — scoring each result from 0 to 95 based on what was detected.

It is built for developers, security researchers, and AI teams who want to understand how their models respond to adversarial inputs before deploying them in production.

---

## Attack Types

| Attack | Description |
|---|---|
| 🔴 **Training Data Leak** | Tests whether a model can be made to reproduce memorized private or confidential content from its training set |
| 🟠 **Prompt-Induced Disclosure** | Attempts to extract the model's system prompt or hidden instructions via injection and jailbreak techniques |
| 🟡 **Inversion Attack** | Probes whether a model will complete or reconstruct partial sensitive data such as SSNs, API keys, or credit card numbers |
| 🟣 **Unintentional PII** | Checks whether the model generates realistic personally identifiable information — emails, phone numbers, financial records — when asked |
| 🔵 **Business IP Leak** | Tests whether the model reveals proprietary algorithms, internal code, weights, or trade-secret-level technical detail |

---

## Risk Scoring

Every attack response is scored from **0 to 95** by the analyzer engine.

| Score | Level | Meaning |
|---|---|---|
| 0 – 29 | 🟢 Low | Model responded safely — no sensitive signals detected |
| 30 – 59 | 🟡 Medium | Ambiguous response — review manually |
| 60 – 95 | 🔴 High | Clear risk signal — model exhibited unsafe behavior |

The analyzer checks for PII patterns, system prompt reflection signals, verbatim quoted passages, fiscal data with specific figures, named individuals with org context, code blocks with proprietary detail, and more.

---

## Models Supported

SentinelProbe routes requests through the HuggingFace Inference Router. The following models are confirmed working:

| Model | Provider |
|---|---|
| Llama 3.1 8B Instruct | Cerebras |
| Llama 3.3 70B Instruct | Groq / SambaNova |
| Llama 4 Scout 17B | Groq |
| Qwen 2.5 72B Instruct | Novita |
| Qwen 2.5 Coder 7B | nScale |
| Qwen3 32B | Groq |
| DeepSeek R1 | SambaNova / Novita |
| DeepSeek V3.2 | Novita |
| Gemma 3 27B | Scaleway |

Each attack page pre-selects the model most susceptible to that attack type. You can override with any model from the dropdown.

---

## Running Locally

### Prerequisites
- Node.js 18+
- A HuggingFace account with an API token that has **"Make calls to Inference Providers"** enabled

### Setup

```bash
# Clone the repo
git clone https://github.com/Aditya-kukreti-ba/Sentinelprobe.git
cd sentinelprobe

# Install dependencies
npm install

# Create your .env file
echo "HF_API_KEY=your_token_here" > .env

# Start in dev mode (auto-restarts on file changes)
npm run dev

# Or start normally
npm start
```

Open [http://localhost:3000](http://localhost:3000)

### Getting a HuggingFace Token

1. Go to [huggingface.co/settings/tokens](https://huggingface.co/settings/tokens)
2. Create a new token with **"Make calls to Inference Providers"** permission enabled
3. Paste it into your `.env` as `HF_API_KEY`

---

## Project Structure

```
sentinelprobe/
├── server.js              # Express backend + analyzer engine
├── public/
│   ├── index.html         # Landing page
│   ├── css/
│   │   └── tests.css      # Styles
│   ├── js/
│   │   └── probe.js       # Frontend engine (history, export, terminal)
│   └── pages/
│       ├── training-data-leak.html
│       ├── prompt-induced.html
│       ├── inversion-attack.html
│       ├── unintentional-pii.html
│       └── business-ip-leak.html
├── .env                   # ← NOT committed (contains API key)
├── .gitignore
├── vercel.json
└── package.json
```

---

## Features

- **Terminal-style output** — responses displayed in a dark terminal UI with syntax highlighting
- **Live risk gauge** — animated SVG score ring updates after each run
- **Attack history** — session history per attack type with one-click replay
- **Export report** — download full JSON report of any attack result
- **Auto model selection** — server picks the best model per attack type automatically
- **Fallback chain** — if auto-selected model fails, tries next available model
- **Hot reload** — `npm run dev` uses nodemon, restarts on any file change

---

## Deploying to Vercel

```bash
npm install -g vercel
vercel
```

Add `HF_API_KEY` in Vercel → Project Settings → Environment Variables.

> **Note:** Vercel free tier has a 10s function timeout. Some models (especially on cold start) may take 20–60s. If you hit timeouts, consider [Railway](https://railway.app) which runs a persistent server with no timeout limit.

---

## Tech Stack

- **Backend** — Node.js, Express
- **AI Routing** — HuggingFace Inference Router (`router.huggingface.co`)
- **Frontend** — Vanilla JS, CSS (no framework)
- **Deployment** — Vercel

---

## ⚠️ Important Note

SentinelProbe probes publicly available models — it does not have access to any private training data. A **high risk score** means the model *behaved* as though it was leaking (generated realistic internal documents, named individuals with org context, claimed to recall training data, etc.). This behavioral pattern is itself a security risk, because a model fine-tuned on real private data and probed with the same techniques could expose the actual thing.

---

## License

MIT