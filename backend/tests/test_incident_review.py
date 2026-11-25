from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.api.incidents import ReviewNote, add_review_note, incident_timeline
from app.db import Base
from app.models import Incident, User, UserRole


def test_review_note_records_actor_and_appears_in_timeline():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        user = User(email="analyst@example.invalid", password_hash="unused", role=UserRole.ANALYST)
        incident = Incident(title="Review required", severity="low", evidence={})
        session.add_all([user, incident])
        session.commit()

        entry = add_review_note(incident.id, ReviewNote(text=" Verify source logs "), user, session)
        timeline = incident_timeline(incident.id, user, session)

        assert [item.id for item in timeline] == [entry.id]
        assert entry.actor_id == user.id
        assert entry.detail == "Verify source logs"
