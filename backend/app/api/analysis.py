"""API routes for code analysis."""
import asyncio
import json
import threading
from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse
from typing import Optional

from app.core.models import AnalyzeRequest, AnalyzeResponse, ProjectReport
from app.core.config import settings
from app.services.ingestion import RepoIngestor
from app.services.llm import LLMClient
from app.services.analyzer import CodeAnalyzer
from app.services.file_utils import get_repo_files

router = APIRouter()


@router.post("/analyze", response_model=AnalyzeResponse)
def analyze_repo(request: AnalyzeRequest):
    """Analyze a GitHub repository or local folder."""
    ingestor = None
    try:
        # Determine credentials
        pat = request.github_pat or settings.github_pat

        # Initialize LLM unless running static-only
        if request.static_only:
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

        # Ingest
        ingestor = RepoIngestor(github_pat=pat)
        repo_path, source_type, repo_name = ingestor.ingest(request.source)

        # Discover files
        max_files = request.max_files or settings.max_files
        max_size = request.max_file_size_kb or settings.max_file_size_kb
        files = get_repo_files(repo_path, max_file_size_kb=max_size, max_files=max_files)

        if not files:
            ingestor.cleanup()
            return AnalyzeResponse(success=False, error="No analyzable code files found in the repository.")

        # Analyze
        analyzer = CodeAnalyzer(llm_client, max_file_tokens=settings.max_file_tokens)
        report = analyzer.analyze_repo(repo_path, files, repo_name, source_type, static_only=request.static_only)

        ingestor.cleanup()
        return AnalyzeResponse(success=True, report=report)

    except Exception as e:
        if ingestor:
            ingestor.cleanup()
        raise HTTPException(status_code=500, detail=str(e))


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
        ingestor = None
        error_msg = None
        report = None
        try:
            pat = request.github_pat or settings.github_pat

            if request.static_only:
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
                analyzer = CodeAnalyzer(llm_client, max_file_tokens=settings.max_file_tokens)
                report = analyzer.analyze_repo(repo_path, files, repo_name, source_type, on_progress=on_progress, static_only=request.static_only)
        except Exception as e:
            error_msg = str(e)
            print(f"[stream] analysis exception: {e}", flush=True)
            _tb.print_exc()
        finally:
            if ingestor:
                try:
                    ingestor.cleanup()
                except Exception:
                    pass

        print(f"[stream] analysis done — error={error_msg!r} report={'set' if report else 'None'}", flush=True)

        try:
            if error_msg:
                asyncio.run_coroutine_threadsafe(
                    queue.put({"type": "error", "message": error_msg}), loop
                ).result(timeout=15)
            elif report is None:
                asyncio.run_coroutine_threadsafe(
                    queue.put({"type": "error", "message": "Analyzer returned no report"}), loop
                ).result(timeout=15)
            else:
                print("[stream] serializing report...", flush=True)
                report_dict = report.model_dump(mode="json")
                print(f"[stream] report serialized ({len(json.dumps(report_dict))} bytes), queuing complete event", flush=True)
                asyncio.run_coroutine_threadsafe(
                    queue.put({"type": "complete", "report": report_dict}), loop
                ).result(timeout=30)
                print("[stream] complete event queued", flush=True)
        except Exception as e:
            print(f"[stream] exception delivering result: {e}", flush=True)
            _tb.print_exc()
            try:
                asyncio.run_coroutine_threadsafe(
                    queue.put({"type": "error", "message": f"Failed to deliver result: {e}"}), loop
                ).result(timeout=10)
            except Exception:
                pass
        finally:
            print("[stream] sending sentinel", flush=True)
            try:
                asyncio.run_coroutine_threadsafe(queue.put(None), loop).result(timeout=10)
            except Exception as e:
                print(f"[stream] failed to send sentinel: {e}", flush=True)
            print("[stream] run_sync complete", flush=True)

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
                yield f"data: {json.dumps({'type': 'error', 'message': f'Serialization error: {e}'})}\n\n"
                break

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
