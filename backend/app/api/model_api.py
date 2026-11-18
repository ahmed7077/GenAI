"""Read-only access to locally trained CICIDS2017 model artifacts."""

import json
from functools import lru_cache
from pathlib import Path

import joblib
import pandas as pd
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from app.api.auth import get_current_user
from app.core.config import get_settings
from app.models import User

router = APIRouter(prefix="/models", tags=["models"])


class FlowPredictionRequest(BaseModel):
    """A CICIDS2017 numeric flow record keyed by its original feature names."""

    features: dict[str, float] = Field(min_length=1)


def _artifact_path(name: str) -> Path:
    return Path(get_settings().model_dir) / name


@lru_cache
def _load_artifact(name: str) -> dict:
    path = _artifact_path(name)
    if not path.is_file():
        raise FileNotFoundError(path)
    return joblib.load(path)


@router.get("/status")
async def model_status(user: User = Depends(get_current_user)) -> dict[str, object]:
    metrics_path = _artifact_path("metrics.json")
    forest_path = _artifact_path("random_forest.joblib")
    isolation_path = _artifact_path("isolation_forest.joblib")
    available = metrics_path.is_file() and forest_path.is_file() and isolation_path.is_file()
    metrics = json.loads(metrics_path.read_text(encoding="utf-8")) if metrics_path.is_file() else None
    return {
        "available": available,
        "metrics": metrics,
        "purpose": "CICIDS2017 network-flow classification and anomaly scoring",
        "limitation": "This model cannot validly score host-authentication or GitHub audit events.",
    }


@router.post("/predict")
async def predict_flow(
    payload: FlowPredictionRequest, user: User = Depends(get_current_user)
) -> dict[str, object]:
    try:
        forest_artifact = _load_artifact("random_forest.joblib")
        isolation_artifact = _load_artifact("isolation_forest.joblib")
    except FileNotFoundError as error:
        raise HTTPException(
            status_code=503,
            detail="CICIDS2017 artifacts are not mounted. Train the model and mount the models directory.",
        ) from error

    columns = forest_artifact["columns"]
    missing = [column for column in columns if column not in payload.features]
    if missing:
        raise HTTPException(
            status_code=422,
            detail={"message": "A complete CICIDS2017 flow vector is required.", "missing_features": missing},
        )
    frame = pd.DataFrame([[payload.features[column] for column in columns]], columns=columns)
    forest_values = forest_artifact["imputer"].transform(frame)
    isolation_values = isolation_artifact["imputer"].transform(frame)
    probability = float(forest_artifact["model"].predict_proba(forest_values)[0][1])
    anomaly = bool(isolation_artifact["model"].predict(isolation_values)[0] == -1)
    return {
        "classification": "attack" if probability >= 0.5 else "benign",
        "attack_probability": probability,
        "isolation_forest_anomaly": anomaly,
        "feature_count": len(columns),
        "evidence_note": "This result is a model signal, not an incident verdict. Preserve and review source flow evidence.",
    }
