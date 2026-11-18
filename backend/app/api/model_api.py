"""Read-only access to locally trained CICIDS2017 model artifacts."""

import json
from functools import lru_cache
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile
from pydantic import BaseModel, Field

from app.api.auth import get_current_user
from app.core.config import get_settings
from app.models import User

router = APIRouter(prefix="/models", tags=["models"])


class FlowPredictionRequest(BaseModel):
    """A CICIDS2017 numeric flow record keyed by its original feature names."""

    features: dict[str, float | None] = Field(min_length=1)


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
    frame = pd.DataFrame([[payload.features[column] for column in columns]], columns=columns).apply(pd.to_numeric, errors="coerce")
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
    , row_number: int | None = Query(default=None, ge=1)
) -> dict[str, object]:
    """Extract the first complete CICIDS2017 flow from a user-selected CSV."""
    if not (file.filename or "").lower().endswith(".csv"):
        raise HTTPException(status_code=422, detail="Select a CICIDS2017 CSV file.")
    try:
        # UploadFile is spooled to disk by FastAPI. Read only one row instead of
        # buffering a multi-hundred-megabyte CICIDS file into application memory.
        await file.seek(0)
        chunks = pd.read_csv(file.file, chunksize=50_000)
    except (UnicodeDecodeError, pd.errors.ParserError) as error:
        raise HTTPException(status_code=422, detail="Could not read this CSV file.") from error
    try:
        columns = _load_artifact("random_forest.joblib")["columns"]
    except FileNotFoundError as error:
        raise HTTPException(status_code=503, detail="CICIDS2017 artifacts are not mounted.") from error
    first_row = None
    selected_row = None
    selected_label = None
    selected_index = 0
    offset = 0
    for chunk in chunks:
        chunk.columns = [str(name).strip() for name in chunk.columns]
        if first_row is None:
            first_row = chunk.iloc[0]
        label_column = next((name for name in chunk.columns if name.lower() == "label"), None)
        if row_number is not None and offset < row_number <= offset + len(chunk):
            selected_row = chunk.iloc[row_number - offset - 1]
            selected_label = str(selected_row[label_column]).strip() if label_column else None
            selected_index = row_number
            break
        if label_column:
            labels = chunk[label_column].astype(str).str.strip()
            attacks = chunk[labels.str.upper() != "BENIGN"]
            if not attacks.empty:
                selected_row = attacks.iloc[0]
                selected_label = str(selected_row[label_column]).strip()
                selected_index = offset + int(np.flatnonzero((labels.str.upper() != "BENIGN").to_numpy())[0]) + 1
                break
        offset += len(chunk)
    row = selected_row if selected_row is not None else first_row
    if row is None:
        raise HTTPException(status_code=422, detail="The selected CSV has no flow records.")
    normalized = {str(name).strip(): value for name, value in row.items()}
    missing = [column for column in columns if column not in normalized]
    if missing:
        raise HTTPException(
            status_code=422,
            detail={"message": "This is not a complete CICIDS2017 flow CSV.", "missing_features": missing},
        )
    try:
        features = {
            column: float(value) if np.isfinite(float(value)) else None
            for column, value in ((column, normalized[column]) for column in columns)
        }
    except (TypeError, ValueError) as error:
        raise HTTPException(status_code=422, detail="The selected flow contains non-numeric values.") from error
    return {
        "features": features,
        "feature_count": len(features),
        "filename": file.filename,
        "source_label": selected_label,
        "source_row": selected_index,
        "selection": f"requested row {row_number}" if row_number else ("first non-BENIGN labelled row" if selected_label else "first row (no label column)"),
    }


@router.post("/score-csv")
async def score_flow_csv(
    file: UploadFile = File(...), user: User = Depends(get_current_user)
) -> dict[str, object]:
    """Score every compatible flow in a CSV in bounded-memory chunks."""
    if not (file.filename or "").lower().endswith(".csv"):
        raise HTTPException(status_code=422, detail="Select a CICIDS2017 CSV file.")
    try:
        forest_artifact = _load_artifact("random_forest.joblib")
        isolation_artifact = _load_artifact("isolation_forest.joblib")
        await file.seek(0)
        chunks = pd.read_csv(file.file, chunksize=50_000)
    except (FileNotFoundError, pd.errors.ParserError, UnicodeDecodeError) as error:
        raise HTTPException(status_code=422, detail="Could not read this CICIDS2017 CSV.") from error

    columns = forest_artifact["columns"]
    scored = attacks = anomalies = 0
    probability_total = 0.0
    highest: list[dict[str, object]] = []
    offset = 0
    source_labels: dict[str, int] = {}
    for chunk in chunks:
        chunk.columns = [str(name).strip() for name in chunk.columns]
        missing = [column for column in columns if column not in chunk.columns]
        if missing:
            raise HTTPException(
                status_code=422,
                detail={"message": "This is not a complete CICIDS2017 flow CSV.", "missing_features": missing},
            )
        features = chunk[columns].apply(pd.to_numeric, errors="coerce").replace([np.inf, -np.inf], np.nan)
        forest_values = forest_artifact["imputer"].transform(features)
        isolation_values = isolation_artifact["imputer"].transform(features)
        probabilities = forest_artifact["model"].predict_proba(forest_values)[:, 1]
        anomaly_flags = isolation_artifact["model"].predict(isolation_values) == -1
        label_column = next((name for name in chunk.columns if name.lower() == "label"), None)
        labels = chunk[label_column].astype(str).str.strip() if label_column else None
        if labels is not None:
            for label, count in labels.value_counts().items():
                source_labels[str(label)] = source_labels.get(str(label), 0) + int(count)
        scored += len(chunk)
        attacks += int((probabilities >= 0.5).sum())
        anomalies += int(anomaly_flags.sum())
        probability_total += float(probabilities.sum())
        for position in np.argsort(probabilities)[-5:]:
            highest.append(
                {
                    "row": offset + int(position) + 1,
                    "attack_probability": round(float(probabilities[position]), 6),
                    "isolation_forest_anomaly": bool(anomaly_flags[position]),
                    "source_label": str(labels.iloc[position]) if labels is not None else None,
                }
            )
        highest = sorted(highest, key=lambda item: float(item["attack_probability"]), reverse=True)[:10]
        offset += len(chunk)
    if not scored:
        raise HTTPException(status_code=422, detail="The selected CSV has no flow records.")
    return {
        "filename": file.filename,
        "flows_scored": scored,
        "attack_count": attacks,
        "attack_rate": attacks / scored,
        "anomaly_count": anomalies,
        "anomaly_rate": anomalies / scored,
        "mean_attack_probability": probability_total / scored,
        "highest_risk_flows": highest,
        "source_label_counts": source_labels or None,
        "evidence_note": "Batch results are model signals for analyst review, not incident verdicts.",
    }
