"""Read-only access to locally trained CICIDS2017 model artifacts."""

import json
from io import BytesIO
from functools import lru_cache
from pathlib import Path

import joblib
import pandas as pd
from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
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


@router.post("/flow-sample")
async def load_flow_sample(
    file: UploadFile = File(...), user: User = Depends(get_current_user)
) -> dict[str, object]:
    """Extract the first complete CICIDS2017 flow from a user-selected CSV."""
    if not (file.filename or "").lower().endswith(".csv"):
        raise HTTPException(status_code=422, detail="Select a CICIDS2017 CSV file.")
    content = await file.read()
    if len(content) > 25 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="CSV must be 25 MiB or smaller.")
    try:
        row = pd.read_csv(BytesIO(content), nrows=1)
    except (UnicodeDecodeError, pd.errors.ParserError) as error:
        raise HTTPException(status_code=422, detail="Could not read this CSV file.") from error
    try:
        columns = _load_artifact("random_forest.joblib")["columns"]
    except FileNotFoundError as error:
        raise HTTPException(status_code=503, detail="CICIDS2017 artifacts are not mounted.") from error
    normalized = {str(name).strip(): value for name, value in row.iloc[0].items()}
    missing = [column for column in columns if column not in normalized]
    if missing:
        raise HTTPException(
            status_code=422,
            detail={"message": "This is not a complete CICIDS2017 flow CSV.", "missing_features": missing},
        )
    try:
        features = {column: float(normalized[column]) for column in columns}
    except (TypeError, ValueError) as error:
        raise HTTPException(status_code=422, detail="The selected flow contains non-numeric values.") from error
    return {"features": features, "feature_count": len(features), "filename": file.filename}
