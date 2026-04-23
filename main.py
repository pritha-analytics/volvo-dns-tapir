from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
import httpx
import time
import random
import json
import asyncio
import glob
import os
from datetime import datetime
from typing import Optional

app = FastAPI(title="Volvo DNS TAPIR Security Dashboard")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

KONG_URL = "http://localhost:8000/ai"
GEMINI_MODEL = "google/gemini-2.0-flash-001"

query_logs = []

class DNSQuery(BaseModel):
    domain: str
    user_ip: Optional[str] = "0.0.0.0"
    username: Optional[str] = "anonymous"
    scenario_type: Optional[str] = None

class PromptQuery(BaseModel):
    message: str

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
                         "reason": "Sensitive info / Malicious prompt blocked by Kong DLP", "latency_ms": elapsed, "status": "blocked"}
            query_logs.append(log_entry)
            return {"threat_level": "BLOCKED", "analysis": "⛔ SENSITIVE DATA ALERT: Kong AI Gateway detected and blocked PII / Confidential Info before reaching the AI.",
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


@app.post("/api/chat")
async def chat_with_ai(query: PromptQuery):
    start_time = time.time()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                KONG_URL,
                json={"model": GEMINI_MODEL, "messages": [{"role": "user", "content": query.message}]},
                headers={"Content-Type": "application/json"}
            )
        elapsed = round((time.time() - start_time) * 1000)
        
        if response.status_code == 429:
            return {"blocked": True, "message": "⛔ Rate limit exceeded - Kong Gateway blocked this request", "latency_ms": elapsed, "threat_level": "BLOCKED"}
            
        data = response.json()
        if "error" in data and "prompt pattern is blocked" in str(data.get("error", "")):
            return {"blocked": True, "message": "⛔ SENSITIVE DATA ALERT: Kong AI Gateway detected and blocked PII / Confidential Info before reaching the AI.", "latency_ms": elapsed, "threat_level": "BLOCKED"}
            
        ai_response = data["choices"][0]["message"]["content"]
        
        # log it for stats
        log_entry = {"timestamp": timestamp, "domain": "CHAT_MESSAGE", "user_ip": "[REDACTED]",
                     "username": "[REDACTED]", "threat_level": "LOW", "analysis": ai_response,
                     "latency_ms": elapsed, "tokens_used": data.get("usage", {}).get("total_tokens", 0), "status": "analyzed"}
        query_logs.append(log_entry)
        
        return {"blocked": False, "message": ai_response, "latency_ms": elapsed, "threat_level": "LOW"}
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


# ── MCP AGENT CHAT (Server-Sent Events) ──────────────────────────────────────
KONG_MCP_URL = "http://localhost:8000/mcp/sse"
MAX_TOOL_LOOPS = 5

async def agent_chat_stream(message: str):
    """Run the MCP agentic loop and stream each step as an SSE event."""
    
    def evt(event: str, data: dict) -> str:
        return f"event: {event}\ndata: {json.dumps(data)}\n\n"

    try:
        from mcp.client.sse import sse_client
        from mcp.client.session import ClientSession

        yield evt("step", {"stage": "source", "msg": "Prompt received"})
        yield evt("step", {"stage": "kong", "msg": "Kong AI Gateway — inspecting prompt..."})
        await asyncio.sleep(0.3)

        async with sse_client(KONG_MCP_URL) as streams:
            async with ClientSession(streams[0], streams[1]) as mcp:
                await mcp.initialize()

                tools_response = await mcp.list_tools()
                tool_names = [t.name for t in tools_response.tools]
                llm_tools = [{
                    "type": "function",
                    "function": {
                        "name": t.name,
                        "description": t.description,
                        "parameters": t.inputSchema
                    }
                } for t in tools_response.tools]

                yield evt("step", {"stage": "mcp_discover", "msg": f"MCP tools discovered: {', '.join(tool_names)}"})

                system_prompt = (
                    "You are a helpful Volvo data assistant. You have access to local dataset files via MCP tools.\n"
                    "Before answering data questions, ALWAYS call list_available_files first, then fetch_documents. "
                    "Do NOT write Python code blocks — use actual tool calls only."
                )
                messages = [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": message}
                ]

                async with httpx.AsyncClient(timeout=60.0) as http:
                    for _ in range(MAX_TOOL_LOOPS):
                        yield evt("step", {"stage": "kong", "msg": "Kong — routing to LLM (ai-proxy)..."})

                        resp = await http.post(
                            KONG_URL,
                            json={"model": GEMINI_MODEL, "messages": messages, "tools": llm_tools},
                            headers={"Content-Type": "application/json"}
                        )
                        data = resp.json()

                        if "error" in data:
                            err_msg = data["error"].get("message", str(data["error"]))
                            yield evt("blocked", {"msg": f"⛔ Kong blocked: {err_msg}"})
                            return

                        llm_msg = data["choices"][0].get("message", {})

                        # No more tool calls → final answer
                        if not llm_msg.get("tool_calls"):
                            yield evt("step", {"stage": "ai", "msg": "Gemini responded ✓"})
                            yield evt("step", {"stage": "verdict", "msg": "Response delivered"})
                            yield evt("answer", {"msg": llm_msg.get("content", "")})
                            return

                        messages.append(llm_msg)

                        for tc in llm_msg["tool_calls"]:
                            fn = tc["function"]["name"]
                            args = json.loads(tc["function"]["arguments"])
                            yield evt("step", {"stage": "mcp_call", "msg": f"🛠 LLM called {fn}({args})"})
                            yield evt("step", {"stage": "kong_mcp", "msg": "Kong — routing to MCP server..."})

                            tool_result = await mcp.call_tool(fn, arguments=args)
                            result_text = "\n".join(c.text for c in tool_result.content if c.type == "text")

                            yield evt("step", {"stage": "mcp_result", "msg": f"MCP returned {len(result_text)} chars"})

                            messages.append({
                                "role": "tool",
                                "tool_call_id": tc["id"],
                                "content": result_text,
                                "name": fn
                            })

    except Exception as e:
        yield evt("error", {"msg": str(e)})


@app.post("/api/agent-chat")
async def agent_chat(query: PromptQuery):
    return StreamingResponse(
        agent_chat_stream(query.message),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"}
    )


app.mount("/", StaticFiles(directory="static", html=True), name="static")
