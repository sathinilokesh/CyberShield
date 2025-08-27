# scripts/prepare_drebin.py
import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

LABEL_CANDIDATES = ["class", "malware", "label", "malicious", "target"]

def find_label_column(df: pd.DataFrame) -> str:
    for c in df.columns:
        if c.lower() in LABEL_CANDIDATES:
            return c
    # fallback: if a column has exactly 2 unique values and looks like labels
    for c in df.columns:
        uniques = df[c].dropna().unique()
        if len(uniques) == 2:
            return c
    raise ValueError("Could not find a binary label column. Please rename the label to 'label'.")

def coerce_labels(y: pd.Series) -> pd.Series:
    # Drop missing labels first
    y = y.dropna()

    mapping = {
        "malware": 1, "malicious": 1, "bad": 1, "true": 1, "1": 1, "1.0": 1,
        "benign": 0, "good": 0, "clean": 0, "false": 0, "0": 0, "0.0": 0,
        "s": 1,  # Drebin dataset uses "S" for suspicious/malware
        "b": 0   # Drebin dataset uses "B" for benign
    }

    y_str = y.astype(str).str.lower().str.strip()
    y_mapped = y_str.map(mapping)

    if y_mapped.isna().any():
        raise ValueError(f"Unrecognized labels found: {y_str[y_mapped.isna()].unique()}")

    return y_mapped.astype(int)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", default="data/raw/drebin.csv", help="Path to raw drebin.csv")
    parser.add_argument("--outdir", default="data/processed", help="Output directory")
    parser.add_argument("--val-size", type=float, default=0.2, help="Validation split fraction")
    parser.add_argument("--random-state", type=int, default=42, help="Random seed")
    args = parser.parse_args()

    in_path = Path(args.input)
    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    # Load CSV
    df = pd.read_csv(in_path)

    # Standardize column names
    df.columns = [c.strip().replace(" ", "_").lower() for c in df.columns]

    # Find label column
    label_col = find_label_column(df)

    # Separate features/label
    y_raw = df[label_col]
    X = df.drop(columns=[label_col])

    # Convert non-numeric columns to categorical codes (simple baseline)
    for c in X.columns:
        if not np.issubdtype(X[c].dtype, np.number):
            X[c] = X[c].astype("category").cat.codes

    # Coerce labels to 0/1
    y = coerce_labels(y_raw)
    X = X.loc[y.index] 

    # Basic sanity checks
    assert set(np.unique(y)).issubset({0,1}), "Label must be binary after coercion"

    # Train/val split with stratification
    X_train, X_val, y_train, y_val = train_test_split(
        X, y, test_size=args.val_size, random_state=args.random_state, stratify=y
    )

    # Persist outputs
    X_train.to_csv(outdir / "X_train.csv", index=False)
    X_val.to_csv(outdir / "X_val.csv", index=False)
    y_train.to_csv(outdir / "y_train.csv", index=False)
    y_val.to_csv(outdir / "y_val.csv", index=False)

    # Save simple schema/metadata
    meta = {
        "label_col": label_col,
        "n_features": X.shape[1],  # fixed bug
        "columns": list(X.columns),
        "val_size": args.val_size,
        "random_state": args.random_state,
        "class_distribution": {
            "train": { "malicious(1)": int((y_train==1).sum()), "benign(0)": int((y_train==0).sum()) },
            "val":   { "malicious(1)": int((y_val==1).sum()), "benign(0)": int((y_val==0).sum()) }
        }
    }
    with open(outdir / "schema.json", "w") as f:
        json.dump(meta, f, indent=2)

    print(f"[OK] Wrote processed splits to {outdir}")

if __name__ == "__main__":
    main()
