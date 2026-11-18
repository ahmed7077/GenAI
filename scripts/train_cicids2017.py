import argparse
import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import f1_score, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import train_test_split

from app.ml import require_dataset


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("dataset")
    parser.add_argument("--rows-per-file", type=int, default=50000)
    parser.add_argument("--output", default="models")
    args = parser.parse_args()
    dataset = require_dataset(args.dataset)
    frames = [pd.read_csv(path, nrows=args.rows_per_file, low_memory=False) for path in sorted(dataset.glob("*.csv"))]
    data = pd.concat(frames, ignore_index=True).rename(columns=lambda value: value.strip())
    target = (data.pop("Label").astype(str).str.strip() != "BENIGN").astype(int)
    features = data.select_dtypes(include=[np.number]).replace([np.inf, -np.inf], np.nan)
    imputer = SimpleImputer(strategy="median")
    values = imputer.fit_transform(features)
    train_x, test_x, train_y, test_y = train_test_split(values, target, test_size=.2, stratify=target, random_state=42)
    forest = RandomForestClassifier(n_estimators=150, class_weight="balanced_subsample", n_jobs=-1, random_state=42).fit(train_x, train_y)
    predicted, scores = forest.predict(test_x), forest.predict_proba(test_x)[:, 1]
    anomaly = IsolationForest(contamination=float(train_y.mean()), n_estimators=150, n_jobs=-1, random_state=42).fit(train_x[train_y.to_numpy() == 0])
    anomaly_prediction = (anomaly.predict(test_x) == -1).astype(int)
    metrics = {"records": len(data), "features": features.shape[1], "random_forest": {"precision": precision_score(test_y, predicted), "recall": recall_score(test_y, predicted), "f1": f1_score(test_y, predicted), "roc_auc": roc_auc_score(test_y, scores)}, "isolation_forest": {"precision": precision_score(test_y, anomaly_prediction), "recall": recall_score(test_y, anomaly_prediction), "f1": f1_score(test_y, anomaly_prediction)}}
    output = Path(args.output); output.mkdir(parents=True, exist_ok=True)
    joblib.dump({"model": forest, "imputer": imputer, "columns": list(features)}, output / "random_forest.joblib")
    joblib.dump({"model": anomaly, "imputer": imputer, "columns": list(features)}, output / "isolation_forest.joblib")
    (output / "metrics.json").write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    print(json.dumps(metrics, indent=2))


if __name__ == "__main__":
    main()
