import asyncio

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.ai import GeminiProvider
from app.api.auth import get_current_user, get_session
from app.models import SecurityEvent, User
from app.core.config import get_settings

router = APIRouter(prefix="/chat", tags=["chat"])


class ChatRequest(BaseModel):
    question: str = Field(min_length=1, max_length=2000)


@router.post("")
async def chat(payload: ChatRequest, user: User = Depends(get_current_user), session: Session = Depends(get_session)) -> dict[str, str]:
    events = session.scalars(select(SecurityEvent).order_by(SecurityEvent.occurred_at.desc()).limit(25)).all()
    evidence = "\n".join(
        f"event={event.id}; time={event.occurred_at.isoformat()}; type={event.event_type}; source={event.source_ip}; host={event.host}; outcome={event.outcome}"
        for event in events
    ) or "No stored events are available."
    try:
        answer = await asyncio.wait_for(
            asyncio.to_thread(GeminiProvider().generate, payload.question, evidence),
            timeout=get_settings().ai_timeout_seconds,
        )
    except TimeoutError as error:
        raise HTTPException(
            status_code=504,
            detail="The AI provider did not respond within 30 seconds. Try again or check the configured model.",
        ) from error
    except RuntimeError as error:
        raise HTTPException(status_code=503, detail=str(error)) from error
    except Exception as error:
        if getattr(error, "code", None) == 503:
            raise HTTPException(
                status_code=503,
                detail="Gemini is temporarily unavailable because of provider demand. Please retry in a moment.",
            ) from error
        raise HTTPException(status_code=502, detail="AI provider request failed; no answer was generated.") from error
    return {"answer": answer, "evidence_count": str(len(events))}
