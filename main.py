from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
import httpx
import time
import json
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

# In-memory log store for demo
query_logs = []

class DNSQuery(BaseModel):
    domain: str
    user_ip: Optional[str] = "0.0.0.0"
    username: Optional[str] = "anonymous"

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
                json={
                    "model": GEMINI_MODEL,
                    "messages": [{"role": "user", "content": message}]
                },
                headers={"Content-Type": "application/json"}
            )

        elapsed = round((time.time() - start_time) * 1000)

        if response.status_code == 429:
            log_entry = {
                "timestamp": timestamp,
                "domain": query.domain,
                "user_ip": query.user_ip,
                "username": query.username,
                "threat_level": "BLOCKED",
                "reason": "Rate limit exceeded by Kong Gateway",
                "latency_ms": elapsed,
                "status": "rate_limited"
            }
            query_logs.append(log_entry)
            raise HTTPException(status_code=429, detail="Rate limit exceeded - Kong Gateway blocked this request")

        data = response.json()

        if "error" in data and "prompt pattern is blocked" in str(data.get("error", "")):
            log_entry = {
                "timestamp": timestamp,
                "domain": query.domain,
                "user_ip": query.user_ip,
                "username": query.username,
                "threat_level": "BLOCKED",
                "reason": "Malicious prompt detected and blocked by Kong",
                "latency_ms": elapsed,
                "status": "blocked"
            }
            query_logs.append(log_entry)
            return {"threat_level": "BLOCKED", "analysis": "⛔ Malicious prompt detected and blocked by Kong AI Gateway", "latency_ms": elapsed, "sanitized": True}

        ai_response = data["choices"][0]["message"]["content"]

        # Parse threat level
        threat_level = "UNKNOWN"
        if "HIGH" in ai_response.upper():
            threat_level = "HIGH"
        elif "MEDIUM" in ai_response.upper():
            threat_level = "MEDIUM"
        elif "LOW" in ai_response.upper():
            threat_level = "LOW"

        log_entry = {
            "timestamp": timestamp,
            "domain": query.domain,
            "user_ip": "[REDACTED]",
            "username": "[REDACTED]",
            "threat_level": threat_level,
            "analysis": ai_response,
            "latency_ms": elapsed,
            "tokens_used": data.get("usage", {}).get("total_tokens", 0),
            "status": "analyzed"
        }
        query_logs.append(log_entry)

        return {
            "threat_level": threat_level,
            "analysis": ai_response,
            "latency_ms": elapsed,
            "tokens_used": data.get("usage", {}).get("total_tokens", 0),
            "sanitized": True,
            "timestamp": timestamp
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/test-prompt-injection")
async def test_prompt_injection(query: PromptQuery):
    """Test if malicious prompts are blocked by Kong"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                KONG_URL,
                json={
                    "model": GEMINI_MODEL,
                    "messages": [{"role": "user", "content": query.message}]
                },
                headers={"Content-Type": "application/json"}
            )

        data = response.json()

        if "error" in data:
            log_entry = {
                "timestamp": timestamp,
                "domain": "PROMPT_INJECTION_ATTEMPT",
                "user_ip": "[REDACTED]",
                "username": "[REDACTED]",
                "threat_level": "BLOCKED",
                "reason": "Prompt injection detected",
                "latency_ms": 0,
                "status": "blocked"
            }
            query_logs.append(log_entry)
            return {"blocked": True, "message": "⛔ Kong AI Gateway blocked this malicious prompt!"}

        return {"blocked": False, "message": data["choices"][0]["message"]["content"]}

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/logs")
async def get_logs():
    return {"logs": list(reversed(query_logs[-50:]))}


@app.get("/api/stats")
async def get_stats():
    total = len(query_logs)
    high = sum(1 for l in query_logs if l.get("threat_level") == "HIGH")
    medium = sum(1 for l in query_logs if l.get("threat_level") == "MEDIUM")
    low = sum(1 for l in query_logs if l.get("threat_level") == "LOW")
    blocked = sum(1 for l in query_logs if l.get("threat_level") == "BLOCKED")
    avg_latency = round(sum(l.get("latency_ms", 0) for l in query_logs) / total) if total > 0 else 0

    return {
        "total_queries": total,
        "high_threats": high,
        "medium_threats": medium,
        "low_threats": low,
        "blocked_requests": blocked,
        "avg_latency_ms": avg_latency
    }


app.mount("/", StaticFiles(directory="static", html=True), name="static")