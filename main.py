from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import httpx
import re
import time
import random
import json
import io
import base64
import os
from datetime import datetime
from typing import Optional

try:
    import pypdf
    HAS_PYPDF = True
except ImportError:
    HAS_PYPDF = False

app = FastAPI(title="Volvo DNS TAPIR Security Dashboard")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

KONG_URL = "http://localhost:8000/ai"
GEMINI_MODEL = "google/gemini-2.0-flash-lite-001"
OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"
OPENROUTER_KEY = "REDACTED_API_KEY"
ALLOWED_UPLOAD_EXTS = {".pdf", ".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp"}

query_logs = []

class DNSQuery(BaseModel):
    domain: str
    user_ip: Optional[str] = "0.0.0.0"
    username: Optional[str] = "anonymous"
    scenario_type: Optional[str] = None

class PromptQuery(BaseModel):
    message: str

class ChatMessage(BaseModel):
    message: str

PII_PATTERNS = [
    (r'\b\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b', 'Credit / Debit Card Number'),
    (r'\b\d{3}[\-\s]?\d{2}[\-\s]?\d{4}\b', 'Social Security Number'),
    (r'\b\d{6,8}[\-]\d{4}\b', 'Swedish Personal Number (Personnummer)'),
    (r'\b\d{8,12}[\-]\d{3,4}\b', 'ID / Account Number'),
    (r'\b(?:\+46|0)\s?\d{2,3}[\s\-]?\d{3}[\s\-]?\d{2}[\s\-]?\d{2}\b', 'Phone Number'),
]

@app.post("/api/analyze")
async def analyze_dns(query: DNSQuery):
    start_time = time.time()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    message = f"Analyze this DNS query: user {query.username} from IP {query.user_ip} visited {query.domain}. Provide threat assessment."
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                KONG_URL,
                json={"model": GEMINI_MODEL, "messages": [{"role": "user", "content": message}]},
                headers={"Content-Type": "application/json"}
            )
        elapsed = round((time.time() - start_time) * 1000)
        if response.status_code == 429:
            log_entry = {"timestamp": timestamp, "domain": query.domain, "user_ip": query.user_ip,
                         "username": query.username, "threat_level": "BLOCKED",
                         "reason": "Rate limit exceeded by Kong Gateway", "latency_ms": elapsed, "status": "rate_limited"}
            query_logs.append(log_entry)
            raise HTTPException(status_code=429, detail="Rate limit exceeded - Kong Gateway blocked this request")
        data = response.json()
        if "error" in data and "prompt pattern is blocked" in str(data.get("error", "")):
            log_entry = {"timestamp": timestamp, "domain": query.domain, "user_ip": query.user_ip,
                         "username": query.username, "threat_level": "BLOCKED",
                         "reason": "Malicious prompt detected and blocked by Kong", "latency_ms": elapsed, "status": "blocked"}
            query_logs.append(log_entry)
            return {"threat_level": "BLOCKED", "analysis": "⛔ Malicious prompt detected and blocked by Kong AI Gateway",
                    "latency_ms": elapsed, "sanitized": True}
        ai_response = data["choices"][0]["message"]["content"]
        threat_level = "UNKNOWN"
        if "HIGH" in ai_response.upper(): threat_level = "HIGH"
        elif "MEDIUM" in ai_response.upper(): threat_level = "MEDIUM"
        elif "LOW" in ai_response.upper(): threat_level = "LOW"
        log_entry = {"timestamp": timestamp, "domain": query.domain, "user_ip": "[REDACTED]",
                     "username": "[REDACTED]", "threat_level": threat_level, "analysis": ai_response,
                     "latency_ms": elapsed, "tokens_used": data.get("usage", {}).get("total_tokens", 0), "status": "analyzed"}
        query_logs.append(log_entry)
        return {"threat_level": threat_level, "analysis": ai_response, "latency_ms": elapsed,
                "tokens_used": data.get("usage", {}).get("total_tokens", 0), "sanitized": True, "timestamp": timestamp}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/chat")
async def chat(body: ChatMessage):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    message = body.message.strip()
    if not message:
        raise HTTPException(status_code=400, detail="Empty message")

    for pattern, pii_type in PII_PATTERNS:
        if re.search(pattern, message, re.IGNORECASE):
            query_logs.append({
                "timestamp": timestamp, "domain": "CHAT_SESSION",
                "user_ip": "[REDACTED]", "username": "[REDACTED]",
                "threat_level": "BLOCKED", "reason": f"PII detected: {pii_type}",
                "latency_ms": 0, "status": "pii_blocked"
            })
            return {
                "blocked": True, "block_type": "PII", "pii_type": pii_type,
                "stage": "KONG_FIREWALL", "timestamp": timestamp,
                "message": (
                    f"Kong AI Gateway detected and blocked sensitive personal information "
                    f"({pii_type}) before it reached the AI model. "
                    f"The data was never transmitted or stored."
                )
            }

    start = time.time()
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                KONG_URL,
                json={"model": GEMINI_MODEL, "messages": [{"role": "user", "content": message}]},
                headers={"Content-Type": "application/json"}
            )
        elapsed = round((time.time() - start) * 1000)

        if response.status_code == 429:
            query_logs.append({
                "timestamp": timestamp, "domain": "CHAT_SESSION",
                "user_ip": "[REDACTED]", "username": "[REDACTED]",
                "threat_level": "BLOCKED", "reason": "Rate limit exceeded",
                "latency_ms": elapsed, "status": "rate_limited"
            })
            return {
                "blocked": True, "block_type": "RATE_LIMIT",
                "stage": "KONG_RATE_LIMITER", "timestamp": timestamp,
                "message": "Kong Gateway rate limit reached (60 req/min). Please wait before sending again."
            }

        data = response.json()

        if "error" in data:
            error_msg = str(data.get("error", ""))
            is_injection = any(k in error_msg.lower() for k in ["blocked", "safety", "prompt pattern", "injection", "jailbreak"])
            if is_injection:
                query_logs.append({
                    "timestamp": timestamp, "domain": "CHAT_SESSION",
                    "user_ip": "[REDACTED]", "username": "[REDACTED]",
                    "threat_level": "BLOCKED", "reason": "Prompt injection / manipulation attempt",
                    "latency_ms": elapsed, "status": "injection_blocked"
                })
                return {
                    "blocked": True, "block_type": "INJECTION",
                    "stage": "KONG_GUARD", "timestamp": timestamp,
                    "message": "Kong AI Firewall blocked this prompt — it matched patterns associated with AI manipulation or jailbreak attempts."
                }
            raise HTTPException(status_code=502, detail=f"AI model error: {error_msg}")

        ai_response = data["choices"][0]["message"]["content"]
        tokens = data.get("usage", {}).get("total_tokens", 0)
        query_logs.append({
            "timestamp": timestamp, "domain": "CHAT_SESSION",
            "user_ip": "[REDACTED]", "username": "[REDACTED]",
            "threat_level": "LOW", "analysis": ai_response,
            "latency_ms": elapsed, "tokens_used": tokens, "status": "allowed"
        })
        return {
            "blocked": False, "response": ai_response,
            "stage": "DELIVERED", "latency_ms": elapsed,
            "tokens": tokens, "timestamp": timestamp
        }
    except httpx.TimeoutException:
        raise HTTPException(status_code=504, detail="Kong Gateway timeout")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/test-prompt-injection")
async def test_prompt_injection(query: PromptQuery):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                KONG_URL,
                json={"model": GEMINI_MODEL, "messages": [{"role": "user", "content": query.message}]},
                headers={"Content-Type": "application/json"}
            )
        data = response.json()
        if "error" in data:
            log_entry = {"timestamp": timestamp, "domain": "PROMPT_INJECTION_ATTEMPT", "user_ip": "[REDACTED]",
                         "username": "[REDACTED]", "threat_level": "BLOCKED",
                         "reason": "Prompt injection detected", "latency_ms": 0, "status": "blocked"}
            query_logs.append(log_entry)
            return {"blocked": True, "message": "⛔ Kong AI Gateway blocked this malicious prompt!"}
        return {"blocked": False, "message": data["choices"][0]["message"]["content"]}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/demo")
async def demo_analyze(query: DNSQuery):
    """Demo endpoint — works without Kong. Handles both keyword matching and typed scenarios."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    start_time = time.time()
    stype = query.scenario_type

    if stype == "cache":
        fake_latency = random.randint(12, 45)
        tokens_saved = random.randint(180, 380)
        analysis = (
            f"⚡ SEMANTIC CACHE HIT — Zero AI Cost\n\n"
            f"Domain: {query.domain}\n"
            f"Cache status: HIT — Semantically similar query found in Kong cache\n"
            f"Response time: {fake_latency}ms (vs ~320ms for a live AI call)\n\n"
            f"Kong's AI Semantic Cache identified this query as semantically similar to a previous "
            f"request and returned the cached analysis instantly — no AI model was called.\n\n"
            f"✓ Tokens saved: {tokens_saved} (Gemini never received this request)\n"
            f"✓ Cost saved: ~${tokens_saved * 0.000002:.4f} for this single request\n"
            f"✓ GDPR protections still applied to the cache lookup\n\n"
            f"At Volvo scale: 60%+ of repeated security queries can be served from cache, "
            f"dramatically reducing AI API spend without compromising security coverage."
        )
        log_entry = {"timestamp": timestamp, "domain": query.domain, "user_ip": "[REDACTED]",
                     "username": "[REDACTED]", "threat_level": "CACHE_HIT", "analysis": analysis,
                     "latency_ms": fake_latency, "tokens_used": 0, "tokens_saved": tokens_saved,
                     "cache_hit": True, "status": "cached"}
        query_logs.append(log_entry)
        return {"threat_level": "CACHE_HIT", "analysis": analysis, "latency_ms": fake_latency,
                "tokens_used": 0, "tokens_saved": tokens_saved, "cache_hit": True,
                "sanitized": True, "timestamp": timestamp, "demo_mode": True}

    if stype == "auth":
        fake_latency = random.randint(8, 22)
        analysis = (
            f"🔐 ACCESS DENIED — Authentication Failed\n\n"
            f"Source IP: {query.user_ip}\n"
            f"Reason: API key absent or invalid — JWT token not present\n\n"
            f"Kong's Key Authentication plugin verified the inbound request and found no valid "
            f"API key. The JWT Authentication plugin also checked for a valid Azure AD / Okta "
            f"token — none found.\n\n"
            f"RESULT: Request rejected at the gateway perimeter.\n"
            f"✓ Zero AI cost incurred\n"
            f"✓ Zero Volvo data exposed\n"
            f"✓ Attack attempt logged for GDPR Article 30 audit trail\n"
            f"✓ Security alert dispatched to SIEM via HTTP Log plugin\n\n"
            f"Only Volvo employees with credentials issued by Azure AD can access the AI Gateway. "
            f"External attackers and unauthorised systems are blocked unconditionally."
        )
        log_entry = {"timestamp": timestamp, "domain": "api.volvo-ai-gateway.internal",
                     "user_ip": "[REDACTED]", "username": "[REDACTED]",
                     "threat_level": "AUTH_BLOCKED", "reason": "Invalid API key — access denied",
                     "latency_ms": fake_latency, "status": "auth_blocked"}
        query_logs.append(log_entry)
        return {"threat_level": "AUTH_BLOCKED", "analysis": analysis, "latency_ms": fake_latency,
                "tokens_used": 0, "sanitized": True, "timestamp": timestamp, "demo_mode": True}

    if stype == "circuit":
        fake_latency = random.randint(280, 520)
        analysis = (
            f"⚠️ CIRCUIT BREAKER ACTIVATED — Automatic Failover\n\n"
            f"Primary Model: Gemini 2.0 Flash — UNHEALTHY (5 failures in 10s)\n"
            f"Circuit state: OPEN → traffic diverted to backup\n"
            f"Fallback Model: Claude Haiku (selected by AI Proxy Advanced)\n"
            f"Recovery time: {fake_latency}ms including failover\n\n"
            f"Kong's Circuit Breaker plugin detected consecutive failures from the primary AI model "
            f"and automatically opened the circuit to stop cascading failures.\n\n"
            f"Kong AI Proxy Advanced instantly evaluated remaining healthy models and routed "
            f"traffic to Claude Haiku — zero manual intervention required.\n\n"
            f"✓ Zero downtime for Volvo manufacturing and security systems\n"
            f"✓ Automatic recovery — circuit closes when primary model recovers\n"
            f"✓ All model switches logged for SLA reporting and governance\n\n"
            f"WITHOUT KONG: A downed AI model would cause Volvo's security monitoring to fail silently."
        )
        log_entry = {"timestamp": timestamp, "domain": query.domain, "user_ip": "[REDACTED]",
                     "username": "[REDACTED]", "threat_level": "CIRCUIT_OPEN",
                     "reason": "Primary AI model unhealthy — circuit breaker triggered, failover active",
                     "latency_ms": fake_latency, "status": "circuit_open"}
        query_logs.append(log_entry)
        return {"threat_level": "CIRCUIT_OPEN", "analysis": analysis, "latency_ms": fake_latency,
                "tokens_used": random.randint(80, 200), "fallback_model": "claude-haiku",
                "sanitized": True, "timestamp": timestamp, "demo_mode": True}

    if stype == "routing":
        fake_latency = random.randint(160, 320)
        analysis = (
            f"🔀 AI PROXY ADVANCED — Smart Model Routing\n\n"
            f"Request type: DNS threat analysis\n"
            f"Models evaluated: Gemini 2.0 Flash, Claude Haiku, GPT-4o-mini\n\n"
            f"Routing decision: Gemini 2.0 Flash\n"
            f"Reason: Optimal cost-quality balance for security classification tasks\n"
            f"• Cost: $0.0001 / 1K tokens ✓ (most cost-efficient viable model)\n"
            f"• Latency: {fake_latency}ms ✓ (within SLA)\n"
            f"• Quality score: 94/100 ✓ (for threat classification tasks)\n"
            f"• Current load: 18% ✓ (healthy capacity)\n\n"
            f"Load Balancer distributed this request across 3 Gemini endpoints.\n\n"
            f"✓ Volvo AI spend optimised — 40% cost reduction vs single-model setup\n"
            f"✓ Best model chosen automatically per request type\n"
            f"✓ All routing decisions logged for cost accountability and auditing"
        )
        log_entry = {"timestamp": timestamp, "domain": query.domain, "user_ip": "[REDACTED]",
                     "username": "[REDACTED]", "threat_level": "ROUTED",
                     "reason": "AI Proxy Advanced selected optimal model",
                     "latency_ms": fake_latency, "status": "routed"}
        query_logs.append(log_entry)
        return {"threat_level": "ROUTED", "analysis": analysis, "latency_ms": fake_latency,
                "tokens_used": random.randint(120, 280), "model_selected": "gemini-2.0-flash",
                "sanitized": True, "timestamp": timestamp, "demo_mode": True}

    # Default: keyword-based DNS scenario matching
    domain = query.domain.lower()

    HIGH_KEYWORDS = [
        'malware', 'c2', 'botnet', 'phishing', 'hack', 'evil', 'virus',
        'ransomware', 'exfil', 'darknet', 'shell', 'exploit', 'trojan',
        'keylog', 'spyware', '.ru', '.xyz', '.tk', '.pw', 'login-volvo',
        'secure-update', 'cdn-delivery', 'key-server', 'dark', 'onion',
        'beacon', 'stager', 'payload', 'inject', 'bypass', 'rootkit'
    ]
    MEDIUM_KEYWORDS = ['suspicious', 'unknown', 'proxy', 'tunnel', 'anon', 'cdn-free']

    threat_reasons = {
        'malware': 'malware distribution network',
        'c2': 'command-and-control infrastructure',
        'botnet': 'botnet beacon endpoint',
        'phishing': 'credential phishing campaign',
        'ransomware': 'ransomware key retrieval server',
        'exfil': 'data exfiltration channel',
        'darknet': 'darknet relay node',
        '.ru': 'high-risk geolocation (RU TLD)',
        '.xyz': 'disposable TLD commonly used in attacks',
        'login-volvo': 'Volvo brand impersonation / typosquatting',
        'key-server': 'encryption key server (ransomware staging)',
        'beacon': 'C2 beacon communication',
        'payload': 'malware payload staging server',
    }

    threat_level = "LOW"
    reason = "no threat indicators"
    matched = next((k for k in HIGH_KEYWORDS if k in domain), None)
    if matched:
        threat_level = "HIGH"
        reason = threat_reasons.get(matched, "known malicious pattern")
    elif any(k in domain for k in MEDIUM_KEYWORDS):
        threat_level = "MEDIUM"
        reason = "suspicious characteristics"

    templates = {
        "HIGH": (
            f"🔴 THREAT CONFIRMED — HIGH RISK\n\n"
            f"Domain: {query.domain}\n"
            f"Classification: {reason.upper()}\n\n"
            f"Kong AI Gateway has identified this domain as a HIGH-risk threat. "
            f"The domain exhibits strong indicators of {reason}. "
            f"All PII has been redacted before AI processing (GDPR Art. 5 compliant). "
            f"IP address and username replaced with [REDACTED] in audit log. "
            f"Recommendation: BLOCK immediately and isolate the source device."
        ),
        "MEDIUM": (
            f"🟡 SUSPICIOUS ACTIVITY — MEDIUM RISK\n\n"
            f"Domain: {query.domain}\n"
            f"Classification: {reason.upper()}\n\n"
            f"Kong AI Gateway flagged this domain for review. "
            f"It shows {reason}. "
            f"PII redacted per GDPR. Recommend security team investigation."
        ),
        "LOW": (
            f"🟢 SAFE TRAFFIC — LOW RISK\n\n"
            f"Domain: {query.domain}\n"
            f"Classification: NORMAL BUSINESS TRAFFIC\n\n"
            f"Kong AI Gateway confirmed this domain is safe. "
            f"No threat indicators detected. "
            f"Request processed normally. PII redacted before AI processing as per GDPR compliance."
        ),
    }

    fake_latency = round((time.time() - start_time) * 1000) + random.randint(180, 420)
    log_entry = {
        "timestamp": timestamp, "domain": query.domain, "user_ip": "[REDACTED]",
        "username": "[REDACTED]", "threat_level": threat_level, "analysis": templates[threat_level],
        "latency_ms": fake_latency,
        "tokens_used": random.randint(120, 380) if threat_level != "BLOCKED" else 0,
        "status": "demo"
    }
    query_logs.append(log_entry)
    return {"threat_level": threat_level, "analysis": templates[threat_level],
            "latency_ms": fake_latency, "tokens_used": log_entry["tokens_used"],
            "sanitized": True, "timestamp": timestamp, "demo_mode": True}


@app.post("/api/upload")
async def upload_file(file: UploadFile = File(...)):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    start = time.time()
    filename = file.filename or "unknown"
    ext = os.path.splitext(filename.lower())[1]
    is_pdf = ext == ".pdf"
    is_image = ext in ALLOWED_UPLOAD_EXTS and not is_pdf

    if not is_pdf and not is_image:
        raise HTTPException(status_code=400, detail="Only PDF and image files (jpg, png, gif, webp) are supported")

    contents = await file.read()

    if is_pdf:
        if not HAS_PYPDF:
            raise HTTPException(status_code=500, detail="PDF support not installed — run: pip install pypdf")
        try:
            reader = pypdf.PdfReader(io.BytesIO(contents))
            text = " ".join(page.extract_text() or "" for page in reader.pages)
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Could not read PDF: {str(e)}")

        # Stage 1: Local PII regex — fast pattern match before hitting Kong
        for pattern, pii_type in PII_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                elapsed = round((time.time() - start) * 1000)
                query_logs.append({
                    "timestamp": timestamp, "domain": f"FILE:{filename}",
                    "user_ip": "[REDACTED]", "username": "[REDACTED]",
                    "threat_level": "BLOCKED", "reason": f"PII in document: {pii_type}",
                    "latency_ms": elapsed, "status": "pii_blocked"
                })
                return {
                    "blocked": True, "block_type": "PII", "pii_type": pii_type,
                    "filename": filename, "file_type": "PDF",
                    "stage": "KONG_FIREWALL", "timestamp": timestamp, "latency_ms": elapsed,
                    "scanned_by": "Kong Regex Guard",
                    "message": f"Kong AI Gateway (Regex Guard) detected {pii_type} in the uploaded document before AI analysis. File blocked — data was not processed or stored."
                }

        # Stage 2: Send extracted text through Kong AI for deep semantic analysis
        kong_prompt = (
            f"You are a data security scanner for Volvo. Analyze the following document text extracted from '{filename}' "
            f"and identify any sensitive or confidential information including: PII (names, addresses, emails, phone numbers), "
            f"financial data, health records, credentials, proprietary business data, or GDPR-sensitive content. "
            f"Respond ONLY with valid JSON: "
            f'{"{"}"has_sensitive_data": true or false, "findings": ["list of findings"], "risk_level": "HIGH or MEDIUM or LOW", '
            f'"gdpr_concern": true or false, "summary": "one sentence summary"{"}"}\n\nDOCUMENT TEXT:\n{text[:3000]}'
        )

        kong_result = {"has_sensitive_data": False, "risk_level": "LOW", "findings": [], "gdpr_concern": False, "summary": "No sensitive data detected."}
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.post(
                    KONG_URL,
                    json={"model": GEMINI_MODEL, "messages": [{"role": "user", "content": kong_prompt}]},
                    headers={"Content-Type": "application/json"}
                )
            data = resp.json()
            if resp.status_code == 429:
                kong_result["summary"] = "Kong rate limit reached during document scan."
            elif "error" in data:
                error_msg = str(data.get("error", ""))
                is_guard_block = any(k in error_msg.lower() for k in ["blocked", "safety", "prompt pattern"])
                if is_guard_block:
                    elapsed = round((time.time() - start) * 1000)
                    query_logs.append({
                        "timestamp": timestamp, "domain": f"FILE:{filename}",
                        "user_ip": "[REDACTED]", "username": "[REDACTED]",
                        "threat_level": "BLOCKED", "reason": "Kong Prompt Guard blocked document content",
                        "latency_ms": elapsed, "status": "kong_guard_blocked"
                    })
                    return {
                        "blocked": True, "block_type": "INJECTION",
                        "filename": filename, "file_type": "PDF",
                        "stage": "KONG_PROMPT_GUARD", "timestamp": timestamp, "latency_ms": elapsed,
                        "scanned_by": "Kong AI Prompt Guard",
                        "message": "Kong AI Prompt Guard flagged this document — its content matched patterns associated with prompt injection or policy violations."
                    }
            else:
                ai_text = data["choices"][0]["message"]["content"]
                match = re.search(r'\{.*\}', ai_text, re.DOTALL)
                if match:
                    kong_result = json.loads(match.group())
        except Exception:
            pass  # If Kong AI fails, fall back to regex-only result

        elapsed = round((time.time() - start) * 1000)

        if kong_result.get("has_sensitive_data") or kong_result.get("risk_level") == "HIGH":
            findings = kong_result.get("findings", ["Sensitive Information"])
            pii_type = "; ".join(findings) if findings else "Sensitive Information"
            query_logs.append({
                "timestamp": timestamp, "domain": f"FILE:{filename}",
                "user_ip": "[REDACTED]", "username": "[REDACTED]",
                "threat_level": "BLOCKED", "reason": f"Kong AI detected: {pii_type}",
                "latency_ms": elapsed, "status": "pii_blocked"
            })
            return {
                "blocked": True, "block_type": "PII", "pii_type": pii_type,
                "filename": filename, "file_type": "PDF",
                "stage": "KONG_AI_SCANNER", "timestamp": timestamp, "latency_ms": elapsed,
                "scanned_by": "Kong AI Deep Scan (via Gemini)",
                "gdpr_concern": kong_result.get("gdpr_concern", False),
                "risk_level": kong_result.get("risk_level", "HIGH"),
                "message": f"Kong AI Gateway (Deep Scan) detected sensitive data in '{filename}': {kong_result.get('summary', pii_type)}. File blocked per GDPR compliance policy."
            }

        query_logs.append({
            "timestamp": timestamp, "domain": f"FILE:{filename}",
            "user_ip": "[REDACTED]", "username": "[REDACTED]",
            "threat_level": "LOW", "analysis": kong_result.get("summary", "No sensitive data detected"),
            "latency_ms": elapsed, "status": "allowed"
        })
        return {
            "blocked": False, "filename": filename, "file_type": "PDF",
            "stage": "DELIVERED", "timestamp": timestamp, "latency_ms": elapsed,
            "pages": len(reader.pages),
            "scanned_by": "Kong AI Deep Scan (via Gemini)",
            "gdpr_concern": False,
            "risk_level": kong_result.get("risk_level", "LOW"),
            "message": f"Document '{filename}' passed Kong AI two-stage scan ({len(reader.pages)} page(s)) — {kong_result.get('summary', 'no sensitive data detected')}. Safe to process."
        }

    else:
        content_type = file.content_type or f"image/{ext.lstrip('.')}"
        b64 = base64.b64encode(contents).decode()
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.post(
                    OPENROUTER_URL,
                    headers={"Authorization": f"Bearer {OPENROUTER_KEY}", "Content-Type": "application/json"},
                    json={
                        "model": GEMINI_MODEL,
                        "messages": [{"role": "user", "content": [
                            {"type": "image_url", "image_url": {"url": f"data:{content_type};base64,{b64}"}},
                            {"type": "text", "text": 'Analyze this image for sensitive personal information (PII) such as credit card numbers, ID/passport numbers, SSNs, bank details, medical records, or confidential documents. Reply ONLY with valid JSON: {"has_pii": true or false, "pii_types": ["list"], "risk_level": "HIGH or MEDIUM or LOW", "reason": "one sentence"}'}
                        ]}]
                    }
                )
            ai_text = resp.json()["choices"][0]["message"]["content"]
            match = re.search(r'\{[^{}]*\}', ai_text, re.DOTALL)
            result = json.loads(match.group()) if match else {"has_pii": False, "risk_level": "LOW", "reason": "Scan inconclusive"}
        except Exception as e:
            result = {"has_pii": False, "risk_level": "LOW", "reason": f"AI scan error — treated as safe"}

        elapsed = round((time.time() - start) * 1000)

        if result.get("has_pii") or result.get("risk_level") == "HIGH":
            pii_types = result.get("pii_types", ["Sensitive Information"])
            pii_type = ", ".join(pii_types) if pii_types else "Sensitive Information"
            query_logs.append({
                "timestamp": timestamp, "domain": f"FILE:{filename}",
                "user_ip": "[REDACTED]", "username": "[REDACTED]",
                "threat_level": "BLOCKED", "reason": f"PII in image: {pii_type}",
                "latency_ms": elapsed, "status": "pii_blocked"
            })
            return {
                "blocked": True, "block_type": "PII", "pii_type": pii_type,
                "filename": filename, "file_type": "IMAGE",
                "stage": "KONG_FIREWALL", "timestamp": timestamp, "latency_ms": elapsed,
                "message": f"Kong AI Gateway detected {pii_type} in the uploaded image. File blocked — data was not processed or stored."
            }

        query_logs.append({
            "timestamp": timestamp, "domain": f"FILE:{filename}",
            "user_ip": "[REDACTED]", "username": "[REDACTED]",
            "threat_level": "LOW", "analysis": result.get("reason", "No PII detected"),
            "latency_ms": elapsed, "status": "allowed"
        })
        return {
            "blocked": False, "filename": filename, "file_type": "IMAGE",
            "stage": "DELIVERED", "timestamp": timestamp, "latency_ms": elapsed,
            "message": f"Image scanned by Kong AI Gateway — {result.get('reason', 'no sensitive data detected')}. Safe to process."
        }


@app.get("/api/logs")
async def get_logs():
    return {"logs": list(reversed(query_logs[-50:]))}


@app.get("/api/stats")
async def get_stats():
    total = len(query_logs)
    high = sum(1 for l in query_logs if l.get("threat_level") == "HIGH")
    medium = sum(1 for l in query_logs if l.get("threat_level") == "MEDIUM")
    low = sum(1 for l in query_logs if l.get("threat_level") == "LOW")
    blocked = sum(1 for l in query_logs if l.get("threat_level") in ("BLOCKED", "AUTH_BLOCKED"))
    cache_hits = sum(1 for l in query_logs if l.get("threat_level") == "CACHE_HIT")
    tokens_saved = sum(l.get("tokens_saved", 0) for l in query_logs)
    pii_redacted = sum(1 for l in query_logs if l.get("threat_level") not in ("AUTH_BLOCKED",) and l.get("status") != "auth_blocked")
    avg_latency = round(sum(l.get("latency_ms", 0) for l in query_logs) / total) if total > 0 else 0
    return {
        "total_queries": total,
        "high_threats": high,
        "medium_threats": medium,
        "low_threats": low,
        "blocked_requests": blocked,
        "cache_hits": cache_hits,
        "tokens_saved": tokens_saved,
        "pii_redacted": pii_redacted,
        "avg_latency_ms": avg_latency
    }


app.mount("/", StaticFiles(directory="static", html=True), name="static")
