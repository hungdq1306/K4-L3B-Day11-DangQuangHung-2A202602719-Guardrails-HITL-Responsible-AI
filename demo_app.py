"""
VinBank Guardrails Interactive Demo UI Server
Run with: python demo_app.py
Access at: http://localhost:8000
"""
from __future__ import annotations

import asyncio
import os
import sys
import time
from pathlib import Path
from typing import Literal

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

# Add src/ to sys.path
_ROOT = Path(__file__).resolve().parent
_SRC = _ROOT / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from dotenv import load_dotenv
load_dotenv(_ROOT / ".env")

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

from guardrails.input_guardrails import detect_injection, topic_filter
from guardrails.output_guardrails import content_filter
from assignment.rate_limiter import RateLimitPlugin
from assignment.pipeline import is_egress_allowed
from core.config import DEMO_SECRET_NOTE, get_red_provider, get_red_model
from core.utils import chat_with_agent
from agents.agent import (
    create_red_agent_default,
    create_blue_agent,
    RED_DEFAULT_INSTRUCTION,
    BLUE_INSTRUCTION,
)
from agents.guards_agent import create_red_agent_advance, RED_ADVANCE_INSTRUCTION

app = FastAPI(title="VinBank Guardrails Demo", version="2.0")

# Global instances for tracking
rate_limiter = RateLimitPlugin(max_requests=10, window_seconds=60)
audit_records: list[dict] = []
metrics = {
    "total_requests": 0,
    "blocked_attacks": 0,
    "blocked_topics": 0,
    "rate_limited": 0,
    "redacted_pii": 0,
    "safe_passed": 0,
}

# Agents cache
_cached_agents = {}

def get_agent_and_runner(mode: str):
    if mode not in _cached_agents:
        if mode == "red":
            agent, runner = create_red_agent_default()
            _cached_agents["red"] = (agent, runner)
        elif mode == "red_advance":
            agent, runner = create_red_agent_advance()
            _cached_agents["red_advance"] = (agent, runner)
        else:  # blue
            from guardrails.input_guardrails import InputGuardrailPlugin
            from guardrails.output_guardrails import OutputGuardrailPlugin
            inp = InputGuardrailPlugin()
            out = OutputGuardrailPlugin(use_llm_judge=False)
            agent, runner = create_blue_agent(plugins=[inp, out])
            _cached_agents["blue"] = (agent, runner)
    return _cached_agents[mode]


class ChatRequest(BaseModel):
    message: str
    mode: Literal["blue", "red", "red_advance"] = "blue"
    user_id: str = "demo_user"
    enable_injection_guard: bool = True
    enable_topic_guard: bool = True
    enable_output_redact: bool = True
    enable_rate_limit: bool = True


@app.post("/api/chat")
async def chat_endpoint(req: ChatRequest):
    start_time = time.time()
    metrics["total_requests"] += 1
    trace = []
    user_msg = req.message.strip()
    user_id = req.user_id or "demo_user"

    # Step 1: Rate Limiter
    if req.enable_rate_limit and req.mode == "blue":
        now = time.time()
        window = rate_limiter.user_windows[user_id]
        while window and window[0] <= now - rate_limiter.window_seconds:
            window.popleft()

        if len(window) >= rate_limiter.max_requests:
            wait = rate_limiter.window_seconds - (now - window[0])
            rate_limiter.blocked_count += 1
            metrics["rate_limited"] += 1
            trace.append({
                "layer": "Rate Limiter",
                "status": "BLOCK",
                "detail": f"Vượt quá {rate_limiter.max_requests} yêu cầu/phút. Thử lại sau {wait:.0f}s.",
            })
            resp_text = f"⚡ [RATE LIMIT] Bạn đã gửi quá nhiều yêu cầu trong thời gian ngắn. Vui lòng đợi {wait:.0f} giây trước khi gửi tiếp."
            audit_entry = {
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "user_id": user_id,
                "input": user_msg,
                "output": resp_text,
                "blocked": True,
                "layer": "rate_limiter",
                "mode": req.mode,
                "latency_ms": round((time.time() - start_time) * 1000, 2),
            }
            audit_records.append(audit_entry)
            return {
                "reply": resp_text,
                "blocked": True,
                "layer": "rate_limiter",
                "trace": trace,
                "metrics": metrics,
            }
        else:
            window.append(now)
            trace.append({
                "layer": "Rate Limiter",
                "status": "ALLOW",
                "detail": f"Window hiện tại: {len(window)}/{rate_limiter.max_requests} requests",
            })

    # Step 2: Input Injection Guardrail
    if req.enable_injection_guard and req.mode in ["blue", "red_advance"]:
        inj_status = detect_injection(user_msg)
        if inj_status == "BLOCK":
            metrics["blocked_attacks"] += 1
            trace.append({
                "layer": "Input Guardrail (Injection)",
                "status": "BLOCK",
                "detail": "Phát hiện mẫu tấn công Prompt Injection / System Override / Zero-width separator.",
            })
            resp_text = "🛡️ [INPUT GUARDRAIL BLOCKED] Yêu cầu của bạn đã bị từ chối vì chứa các mẫu câu lệnh cố tình can thiệp vào chỉ thị hệ thống của VinBank AI."
            audit_entry = {
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "user_id": user_id,
                "input": user_msg,
                "output": resp_text,
                "blocked": True,
                "layer": "input_injection",
                "mode": req.mode,
                "latency_ms": round((time.time() - start_time) * 1000, 2),
            }
            audit_records.append(audit_entry)
            return {
                "reply": resp_text,
                "blocked": True,
                "layer": "input_guardrail",
                "trace": trace,
                "metrics": metrics,
            }
        else:
            trace.append({
                "layer": "Input Guardrail (Injection)",
                "status": "ALLOW",
                "detail": "Không phát hiện dấu hiệu can thiệp prompt",
            })

    # Step 3: Input Topic Filter
    if req.enable_topic_guard and req.mode in ["blue", "red_advance"]:
        top_status = topic_filter(user_msg)
        if top_status == "BLOCK":
            metrics["blocked_topics"] += 1
            trace.append({
                "layer": "Input Guardrail (Topic Filter)",
                "status": "BLOCK",
                "detail": "Nội dung ngoài phạm vi nghiệp vụ ngân hàng hoặc chứa chủ đề bị cấm.",
            })
            resp_text = "🏦 [OFF-TOPIC BLOCKED] VinBank AI Assistant chỉ hỗ trợ các nghiệp vụ tài chính - ngân hàng (tài khoản, tiết kiệm, lãi suất, thẻ, giao dịch chuyển khoản). Vui lòng đặt câu hỏi phù hợp."
            audit_entry = {
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "user_id": user_id,
                "input": user_msg,
                "output": resp_text,
                "blocked": True,
                "layer": "input_topic",
                "mode": req.mode,
                "latency_ms": round((time.time() - start_time) * 1000, 2),
            }
            audit_records.append(audit_entry)
            return {
                "reply": resp_text,
                "blocked": True,
                "layer": "input_guardrail",
                "trace": trace,
                "metrics": metrics,
            }
        else:
            trace.append({
                "layer": "Input Guardrail (Topic Filter)",
                "status": "ALLOW",
                "detail": "Chủ đề nghiệp vụ ngân hàng hợp lệ",
            })

    # Step 4: LLM Inference
    agent, runner = get_agent_and_runner(req.mode)
    trace.append({
        "layer": f"LLM Generation ({req.mode.upper()})",
        "status": "INFERRED",
        "detail": f"Model: {getattr(agent, 'model', 'gemini')}",
    })

    try:
        raw_response, _ = await chat_with_agent(agent, runner, user_msg)
        if not raw_response:
            raw_response = "VinBank xin kính chào Quý khách. Tôi có thể hỗ trợ gì cho bạn hôm nay?"
    except Exception as e:
        raw_response = f"VinBank AI: Đã xử lý yêu cầu. ({e})"

    # Step 5: Output Guardrail (PII & Secret Redaction)
    final_response = raw_response
    if req.enable_output_redact and req.mode in ["blue", "red_advance"]:
        out_res = content_filter(raw_response)
        if not out_res["safe"]:
            metrics["redacted_pii"] += len(out_res["issues"])
            final_response = out_res["redacted"]
            trace.append({
                "layer": "Output Guardrail (PII/Secrets)",
                "status": "REDACTED",
                "detail": f"Đã che {len(out_res['issues'])} thông tin nhạy cảm: {', '.join(out_res['issues'])}",
            })
        else:
            trace.append({
                "layer": "Output Guardrail (PII/Secrets)",
                "status": "CLEAN",
                "detail": "Không có PII hay Secret rò rỉ trong câu trả lời",
            })
    elif req.mode == "red":
        trace.append({
            "layer": "Output Guardrail",
            "status": "BYPASSED",
            "detail": "Red Agent: Không bật bộ lọc Output — có thể lộ thông tin nội bộ!",
        })

    metrics["safe_passed"] += 1
    latency = round((time.time() - start_time) * 1000, 2)
    audit_entry = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "user_id": user_id,
        "input": user_msg,
        "output": final_response,
        "blocked": False,
        "layer": None,
        "mode": req.mode,
        "latency_ms": latency,
    }
    audit_records.append(audit_entry)

    return {
        "reply": final_response,
        "blocked": False,
        "layer": None,
        "trace": trace,
        "metrics": metrics,
        "latency_ms": latency,
    }


@app.get("/api/metrics")
async def get_metrics():
    return {
        "metrics": metrics,
        "audit_count": len(audit_records),
    }


@app.get("/api/audit")
async def get_audit():
    return {
        "logs": audit_records[-30:],  # return last 30 logs
    }


@app.post("/api/reset")
async def reset_state():
    rate_limiter.user_windows.clear()
    rate_limiter.blocked_count = 0
    audit_records.clear()
    for k in metrics:
        metrics[k] = 0
    return {"status": "reset_ok"}


@app.get("/", response_class=HTMLResponse)
async def serve_ui():
    html_path = _ROOT / "static" / "index.html"
    if html_path.exists():
        return html_path.read_text(encoding="utf-8")
    return "<h1>UI file not found. Please ensure static/index.html exists.</h1>"


if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("🚀 VinBank AI Guardrails Interactive Demo UI")
    print("🌐 Mở trình duyệt tại: http://localhost:8000")
    print("=" * 60 + "\n")
    uvicorn.run(app, host="127.0.0.1", port=8000, log_level="info")
