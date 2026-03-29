"""
Local ML pipeline: Isolation Forest with contamination search.
Usage:
  python machine.py path/to/data.csv
  python machine.py ../sample_login_events.csv
"""
import argparse
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import IsolationForest
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler

# ====== Load Dataset ======
parser = argparse.ArgumentParser(description="Run Isolation Forest anomaly detection on a CSV.")
parser.add_argument(
    "csv_path",
    type=Path,
    nargs="?",
    default=None,
    help="Path to input CSV (must include timestamp and user_id columns).",
)
parser.add_argument(
    "-o",
    "--output",
    type=Path,
    default=Path("dataset_with_anomalies.csv"),
    help="Where to write the output CSV (default: dataset_with_anomalies.csv).",
)
args = parser.parse_args()

if args.csv_path is None:
    repo_root = Path(__file__).resolve().parent.parent
    default_csv = repo_root / "sample_login_events.csv"
    if default_csv.is_file():
        args.csv_path = default_csv
        print(f"Using default sample: {args.csv_path}")
    else:
        parser.error("Provide a CSV path, or place sample_login_events.csv in the project root.")

df = pd.read_csv(args.csv_path)

# ====== Feature Engineering ======
df["timestamp"] = pd.to_datetime(df["timestamp"])
df["hour"] = df["timestamp"].dt.hour
df["day_of_week"] = df["timestamp"].dt.dayofweek

if "user_id" not in df.columns:
    raise SystemExit("CSV must include a 'user_id' column.")

X = df.drop(columns=["timestamp", "user_id"])

categorical_cols = X.select_dtypes(include=["object"]).columns.tolist()
numeric_cols = X.select_dtypes(exclude=["object"]).columns.tolist()

preprocessor = ColumnTransformer(
    transformers=[
        ("cat", OneHotEncoder(handle_unknown="ignore"), categorical_cols),
        ("num", StandardScaler(), numeric_cols),
    ]
)

# ====== Automatic Contamination Search ======
best_contamination = None
best_separation = -np.inf

for contamination in np.linspace(0.01, 0.1, 10):
    model = Pipeline(
        steps=[
            ("preprocessor", preprocessor),
            (
                "isoforest",
                IsolationForest(
                    n_estimators=100,
                    contamination=contamination,
                    random_state=42,
                ),
            ),
        ]
    )
    model.fit(X)
    scores = -model.named_steps["isoforest"].decision_function(
        model.named_steps["preprocessor"].transform(X)
    )
    sep = np.percentile(scores, 95) - np.percentile(scores, 5)
    if sep > best_separation:
        best_separation = sep
        best_contamination = contamination
        best_model = model
        best_scores = scores

print(f"Best contamination found: {best_contamination:.2%}")

# ====== Final Model & Output ======
preds = best_model.named_steps["isoforest"].predict(
    best_model.named_steps["preprocessor"].transform(X)
)
df["anomaly_flag"] = np.where(preds == -1, 1, 0)
df["anomaly_score"] = best_scores

args.output.parent.mkdir(parents=True, exist_ok=True)
df.to_csv(args.output, index=False)
print(f"Saved: {args.output.resolve()}")

preview_cols = [c for c in ["user_id", "activity_type", "anomaly_score", "anomaly_flag"] if c in df.columns]
print(df[preview_cols].head(10).to_string())
