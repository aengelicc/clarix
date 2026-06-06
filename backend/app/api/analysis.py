"""API routes for code analysis."""
import asyncio
import contextlib
import json
import threading
import uuid

from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.responses import JSONResponse, StreamingResponse

# Per-job cancel events — keyed by job_id UUID. Never a global singleton.
_cancel_events: dict = {}
_cancel_events_lock = threading.Lock()


class _AnalysisCancelled(Exception):
    pass

from app.core.config import settings
from app.core.models import AnalyzeRequest, AnalyzeResponse, ProjectReport
from app.services.analyzer import CodeAnalyzer
from app.services.file_utils import get_repo_files
from app.services.ingestion import RepoIngestor
from app.services.llm import LLMClient
from app.services.sarif import build_sarif

router = APIRouter()


def _run_analysis(request: AnalyzeRequest, cancel_event: threading.Event | None = None,
                  on_progress=None) -> ProjectReport:
    """Run the full analysis pipeline: ingest, scan, optional LLM. Returns a ProjectReport.

    Raises HTTPException on error and ensures the ingestor is cleaned up.
    """
    ingestor = None
    try:
        pat = request.github_pat or settings.github_pat

        mode = "static" if request.static_only else request.analysis_mode

        if mode == "static":
            llm_client = None
        else:
            provider = request.llm_provider or settings.llm_provider
            if request.api_key:
                api_key = request.api_key
            elif provider == "anthropic":
                api_key = settings.anthropic_api_key
            else:
                api_key = settings.openai_api_key
            model = settings.anthropic_model if provider == "anthropic" else settings.openai_model
            llm_client = LLMClient(provider=provider, api_key=api_key, model=model)

        ingestor = RepoIngestor(github_pat=pat)
        repo_path, source_type, repo_name = ingestor.ingest(request.source)

        max_files = request.max_files or settings.max_files
        max_size = request.max_file_size_kb or settings.max_file_size_kb
        files = get_repo_files(repo_path, max_file_size_kb=max_size, max_files=max_files)

        if not files:
            raise HTTPException(status_code=400, detail="No analyzable code files found in the repository.")

        analyzer = CodeAnalyzer(
            llm_client,
            max_file_tokens=settings.max_file_tokens,
            cancel_event=cancel_event,
            frameworks=request.frameworks,
        )
        report = analyzer.analyze_repo(
            repo_path, files, repo_name, source_type,
            on_progress=on_progress, mode=mode,
        )
        return report
    finally:
        if ingestor:
            with contextlib.suppress(Exception):
                ingestor.cleanup()


@router.post("/analyze/cancel")
async def cancel_analysis(request: Request):
    try:
        body = await request.json()
        job_id = body.get("job_id") if isinstance(body, dict) else None
    except Exception:
        job_id = None
    with _cancel_events_lock:
        if job_id:
            event = _cancel_events.get(job_id)
            if event:
                event.set()
        else:
            for event in _cancel_events.values():
                event.set()
    return {"status": "cancelled"}


@router.post("/analyze", response_model=AnalyzeResponse)
def analyze_repo(request: AnalyzeRequest):
    """Analyze a GitHub repository or local folder."""
    try:
        report = _run_analysis(request)
        return AnalyzeResponse(success=True, report=report)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


@router.post("/analyze/sarif")
def analyze_repo_sarif(request: AnalyzeRequest):
    """Analyze a repository and return SARIF 2.1.0 JSON.

    Returns 200 with a SARIF document on success. On analysis error, returns
    400/500 with a JSON `{"error": "..."}` body (SARIF consumers ignore bodies
    on 4xx, so failure shows up as a missing upload, not a broken report).
    """
    try:
        report = _run_analysis(request)
    except HTTPException as exc:
        return JSONResponse(status_code=exc.status_code, content={"error": exc.detail})
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})

    sarif = build_sarif(report)
    body = json.dumps(sarif, ensure_ascii=False)
    filename = f"clarix-{report.repo_name or 'report'}.sarif"
    return Response(
        content=body,
        media_type="application/sarif+json",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Content-Type": "application/sarif+json; charset=utf-8",
        },
    )


@router.post("/report/sarif")
def report_to_sarif(report: ProjectReport):
    """Convert a ProjectReport (POSTed by the client) into SARIF 2.1.0 JSON.

    Useful for re-exporting an existing report without re-running the analysis.
    """
    sarif = build_sarif(report)
    body = json.dumps(sarif, ensure_ascii=False)
    filename = f"clarix-{report.repo_name or 'report'}.sarif"
    return Response(
        content=body,
        media_type="application/sarif+json",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Content-Type": "application/sarif+json; charset=utf-8",
        },
    )


@router.post("/analyze/stream")
async def analyze_repo_stream(request: AnalyzeRequest):
    """Analyze a repository and stream progress via Server-Sent Events."""
    queue: asyncio.Queue = asyncio.Queue()
    loop = asyncio.get_running_loop()

    def on_progress(message: str, current: int = 0, total: int = 0):
        asyncio.run_coroutine_threadsafe(
            queue.put({"type": "progress", "message": message, "current": current, "total": total}),
            loop,
        )

    def run_sync():
        import traceback as _tb
        job_id = str(uuid.uuid4())
        cancel_event = threading.Event()
        with _cancel_events_lock:
            _cancel_events[job_id] = cancel_event

        # Notify client of the job ID immediately so it can cancel specifically
        asyncio.run_coroutine_threadsafe(
            queue.put({"type": "started", "job_id": job_id}), loop
        )

        ingestor = None
        error_msg = None
        report = None
        cancelled = False
        try:
            pat = request.github_pat or settings.github_pat

            mode = "static" if request.static_only else request.analysis_mode

            if mode == "static":
                llm_client = None
            else:
                provider = request.llm_provider or settings.llm_provider
                if request.api_key:
                    api_key = request.api_key
                elif provider == "anthropic":
                    api_key = settings.anthropic_api_key
                else:
                    api_key = settings.openai_api_key
                model = settings.anthropic_model if provider == "anthropic" else settings.openai_model
                llm_client = LLMClient(provider=provider, api_key=api_key, model=model)

            on_progress("Fetching repository...", 0, 0)
            ingestor = RepoIngestor(github_pat=pat)
            repo_path, source_type, repo_name = ingestor.ingest(request.source)

            on_progress("Scanning files...", 0, 0)
            max_files = request.max_files or settings.max_files
            max_size = request.max_file_size_kb or settings.max_file_size_kb
            files = get_repo_files(repo_path, max_file_size_kb=max_size, max_files=max_files)

            if not files:
                error_msg = "No analyzable code files found in the repository."
            else:
                analyzer = CodeAnalyzer(
                    llm_client,
                    max_file_tokens=settings.max_file_tokens,
                    cancel_event=cancel_event,
                    frameworks=request.frameworks,
                )
                report = analyzer.analyze_repo(
                    repo_path, files, repo_name, source_type,
                    on_progress=on_progress, mode=mode,
                )
        except _AnalysisCancelled:
            cancelled = True
        except Exception as e:
            # Return a generic message to the client; full traceback goes to server logs only.
            error_msg = "Analysis failed due to an internal error. Check server logs for details."
            print(f"[stream] analysis exception [{job_id}]: {e}", flush=True)
            _tb.print_exc()
        finally:
            with _cancel_events_lock:
                _cancel_events.pop(job_id, None)
            if ingestor:
                with contextlib.suppress(Exception):
                    ingestor.cleanup()

        print(f"[stream] analysis done [{job_id}] — error={error_msg!r} report={'set' if report else 'None'}", flush=True)

        try:
            if cancelled:
                asyncio.run_coroutine_threadsafe(
                    queue.put({"type": "cancelled"}), loop
                ).result(timeout=10)
            elif error_msg:
                asyncio.run_coroutine_threadsafe(
                    queue.put({"type": "error", "message": error_msg}), loop
                ).result(timeout=15)
            elif report is None:
                asyncio.run_coroutine_threadsafe(
                    queue.put({"type": "error", "message": "Analyzer returned no report"}), loop
                ).result(timeout=15)
            else:
                print(f"[stream] serializing report [{job_id}]...", flush=True)
                report_dict = report.model_dump(mode="json")
                print(f"[stream] report serialized ({len(json.dumps(report_dict))} bytes), queuing complete event", flush=True)
                asyncio.run_coroutine_threadsafe(
                    queue.put({"type": "complete", "report": report_dict}), loop
                ).result(timeout=30)
                print(f"[stream] complete event queued [{job_id}]", flush=True)
        except Exception as e:
            print(f"[stream] exception delivering result [{job_id}]: {e}", flush=True)
            _tb.print_exc()
            with contextlib.suppress(Exception):
                asyncio.run_coroutine_threadsafe(
                    queue.put({"type": "error", "message": "Failed to deliver result"}), loop
                ).result(timeout=10)
        finally:
            print(f"[stream] sending sentinel [{job_id}]", flush=True)
            try:
                asyncio.run_coroutine_threadsafe(queue.put(None), loop).result(timeout=10)
            except Exception as e:
                print(f"[stream] failed to send sentinel [{job_id}]: {e}", flush=True)
            print(f"[stream] run_sync complete [{job_id}]", flush=True)

    threading.Thread(target=run_sync, daemon=True).start()

    async def generate():
        while True:
            item = await queue.get()
            if item is None:
                break
            try:
                yield f"data: {json.dumps(item)}\n\n"
            except Exception as e:
                print(f"[stream] generator serialization error: {e}", flush=True)
                yield f"data: {json.dumps({'type': 'error', 'message': 'Serialization error'})}\n\n"
                break

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
