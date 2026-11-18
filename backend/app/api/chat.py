from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.ai import GeminiProvider
from app.api.auth import get_current_user, get_session
from app.models import SecurityEvent, User

router = APIRouter(prefix="/chat", tags=["chat"])


class ChatRequest(BaseModel):
    question: str = Field(min_length=3, max_length=2000)


@router.post("")
async def chat(payload: ChatRequest, user: User = Depends(get_current_user), session: Session = Depends(get_session)) -> dict[str, str]:
    events = session.scalars(select(SecurityEvent).order_by(SecurityEvent.occurred_at.desc()).limit(25)).all()
    evidence = "\n".join(
        f"event={event.id}; time={event.occurred_at.isoformat()}; type={event.event_type}; source={event.source_ip}; host={event.host}; outcome={event.outcome}"
        for event in events
    ) or "No stored events are available."
    try:
        answer = GeminiProvider().generate(payload.question, evidence)
    except RuntimeError as error:
        raise HTTPException(status_code=503, detail=str(error)) from error
    except Exception as error:
        raise HTTPException(status_code=502, detail="AI provider request failed; no answer was generated.") from error
    return {"answer": answer, "evidence_count": str(len(events))}
