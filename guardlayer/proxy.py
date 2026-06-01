"""
GuardLayer Proxy Server
-----------------------
FastAPI app that sits between your application and any LLM API.
Every request is scanned before forwarding; every response is scanned before returning.
Blocked requests (score > 60) never reach the LLM.
"""

from __future__ import annotations
import os
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

from guardlayer import __version__
from guardlayer.scanner import scan
from guardlayer.session_store import store
from guardlayer.dashboard import console, print_scan_result


# The real LLM API to forward requests to (set via env var or default to OpenAI)
TARGET_BASE_URL = os.getenv("GUARDLAYER_TARGET", "https://api.openai.com")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Print startup info, then clean up on shutdown."""
    console.print(f"[bold cyan]GuardLayer {__version__}[/bold cyan] proxy listening on [cyan]http://0.0.0.0:8080[/cyan]")
    console.print(f"[dim]Forwarding to: {TARGET_BASE_URL}[/dim]\n")
    yield
    # On shutdown, print session summary
    records = store.all_records()
    if records:
        from guardlayer.dashboard import print_session_summary
        print_session_summary(len(records), store.blocked_count())


app = FastAPI(title="GuardLayer", version=__version__, lifespan=lifespan)


@app.get("/healthz")
async def health_check():
    """Simple health check endpoint."""
    return {"status": "ok", "version": __version__}


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
async def proxy(request: Request, path: str):
    """
    Main proxy handler — intercepts every request, scans it, forwards if safe,
    scans the response, then returns it to the caller.
    """
    # Read the raw request body
    body_bytes = await request.body()
    body_text = body_bytes.decode("utf-8", errors="replace")

    # ── Step 1: Scan the incoming request ────────────────────────────────────
    request_scan = scan(body_text)
    record = store.new_record(
        target_url=f"{TARGET_BASE_URL}/{path}",
        request_scan=request_scan,
    )
    print_scan_result(record)

    # Block if the request is too risky
    if request_scan.blocked:
        return JSONResponse(
            status_code=400,
            content={
                "error": "Request blocked by GuardLayer",
                "risk_score": request_scan.highest_score,
                "findings": [
                    {
                        "category": f.category.value,
                        "risk_score": f.risk_score,
                        "explanation": f.explanation,
                    }
                    for f in request_scan.findings
                ],
            },
        )

    # ── Step 2: Forward the request to the real LLM API ──────────────────────
    forward_url = f"{TARGET_BASE_URL}/{path}"
    forward_headers = {
        key: value
        for key, value in request.headers.items()
        if key.lower() not in ("host", "content-length")
    }

    async with httpx.AsyncClient(timeout=60.0) as client:
        try:
            llm_response = await client.request(
                method=request.method,
                url=forward_url,
                headers=forward_headers,
                content=body_bytes,
                params=dict(request.query_params),
            )
        except httpx.RequestError as exc:
            return JSONResponse(
                status_code=502,
                content={"error": f"Failed to reach LLM API: {exc}"},
            )

    # ── Step 3: Scan the LLM response ────────────────────────────────────────
    response_text = llm_response.content.decode("utf-8", errors="replace")
    response_scan = scan(response_text)
    store.update_response(record.record_id, response_scan)

    # Block the response if it contains sensitive data
    if response_scan.blocked:
        return JSONResponse(
            status_code=200,
            content={
                "error": "Response blocked by GuardLayer — sensitive data detected",
                "risk_score": response_scan.highest_score,
                "findings": [
                    {
                        "category": f.category.value,
                        "risk_score": f.risk_score,
                        "explanation": f.explanation,
                    }
                    for f in response_scan.findings
                ],
            },
        )

    # Return the clean response to the caller
    return Response(
        content=llm_response.content,
        status_code=llm_response.status_code,
        headers=dict(llm_response.headers),
        media_type=llm_response.headers.get("content-type"),
    )
