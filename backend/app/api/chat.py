import asyncio

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.ai import GeminiProvider
from app.api.auth import get_current_user, get_session
from app.models import SecurityEvent, User
from app.rag import retrieve
from app.core.config import get_settings

router = APIRouter(prefix="/chat", tags=["chat"])


class ChatRequest(BaseModel):
    question: str = Field(min_length=1, max_length=2000)


@router.post("")
async def chat(payload: ChatRequest, user: User = Depends(get_current_user), session: Session = Depends(get_session)) -> dict[str, object]:
    events = session.scalars(select(SecurityEvent).order_by(SecurityEvent.occurred_at.desc()).limit(25)).all()
    evidence = "\n".join(
        f"event={event.id}; time={event.occurred_at.isoformat()}; type={event.event_type}; source={event.source_ip}; host={event.host}; outcome={event.outcome}"
        for event in events
    ) or "No stored events are available."
    sources = retrieve(payload.question)
    source_context = "\n".join(
        f"[{source['id']}] {source['title']}: {source['excerpt']} ({source['url']})" for source in sources
    )
    provider = GeminiProvider()
    failures: list[str] = []
    answer = ""
    selected_model = ""
    for model in provider.models():
        try:
            answer = await asyncio.wait_for(
                asyncio.to_thread(provider.generate, model, payload.question, f"{evidence}\n\nTrusted RAG sources:\n{source_context}"),
                timeout=get_settings().ai_model_timeout_seconds,
            )
            selected_model = model
            break
        except TimeoutError:
            failures.append(f"{model} timed out")
        except RuntimeError as error:
            raise HTTPException(status_code=503, detail=str(error)) from error
        except Exception as error:
            failures.append(f"{model} failed (HTTP {getattr(error, 'code', 'unknown')})")
    if not answer:
        selected_model = "local-rag-fallback"
        event_types = sorted({event.event_type for event in events})
        question = payload.question.lower()
        if "review" in question or "first" in question:
            guidance = (
                "Start with workflow-permission changes, merge-setting changes, and OAuth access changes; "
                "compare their actor, repository, approval, and change-ticket context before escalating."
            )
        elif question.strip() in {"hi", "hello", "hey"}:
            guidance = "Ask about a specific event type, a time window, or what should be reviewed first."
        else:
            guidance = (
                "The local fallback can summarize stored event types and retrieve relevant defensive guidance, "
                "but it cannot make unsupported conclusions while Gemini is unavailable."
            )
        answer = (
            "Gemini capacity is unavailable, so ThreatLens switched to its local retrieval fallback. "
            f"It reviewed {len(events)} recent stored event summaries. "
            f"Observed event types include: {', '.join(event_types[:8]) or 'none'}. "
            f"{guidance} This fallback does not infer an incident."
        )
    primary_model = provider.models()[0]
    attempted = "; ".join(failures)
    model_note = (
        f"System note: response generated with {selected_model} after fallback. {attempted}"
        if selected_model not in {primary_model, "local-rag-fallback"}
        else (
            f"System note: all configured Gemini models were unavailable ({attempted}). "
            "Switched to local-rag-fallback."
            if selected_model == "local-rag-fallback"
            else f"System note: response generated with {selected_model}."
        )
    )
    citations = "\n".join(f"- {source['title']}: {source['url']}" for source in sources)
    answer = f"{model_note}\n\n{answer}\n\nRetrieved guidance:\n{citations}"
    return {"answer": answer, "evidence_count": len(events), "sources": sources, "model": selected_model}
