# CICIDS2017 baseline evaluation

## Run

Training ran locally on 18 November 2026 using the official CICIDS2017 `MachineLearningCVE` CSV files. The run read 50,000 rows from each of eight source files (400,000 records total), retained 78 numeric flow features, used a stratified 80/20 split with `random_state=42`, and trained 150 estimators for each model.

## Measured results

| Model | Precision | Recall | F1 | ROC-AUC |
| --- | ---: | ---: | ---: | ---: |
| Random Forest | 0.999848 | 0.998486 | 0.999167 | 0.999917 |
| Isolation Forest | 0.181501 | 0.204631 | 0.192373 | Not applicable |

## Interpretation

The Random Forest result is a strong sampled-dataset baseline, not a claim of real-world detection performance. CICIDS2017 is a 2017 laboratory dataset, and its random stratified split can overstate generalization where related traffic is present in both partitions.

The Isolation Forest baseline performs poorly on this task and must not be promoted as an operational detector without redesign, threshold tuning, and validation on temporally separated or external data.

## Artifacts

The local run created `models/random_forest.joblib`, `models/isolation_forest.joblib`, and `models/metrics.json`. They are deliberately excluded from Git along with the raw dataset.
