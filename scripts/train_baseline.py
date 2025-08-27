# scripts/train_baseline.py
import os
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, roc_auc_score
import joblib

def main():
    # Load processed training and validation data
    X_train = pd.read_csv("data/processed/X_train.csv")
    X_val = pd.read_csv("data/processed/X_val.csv")
    y_train = pd.read_csv("data/processed/y_train.csv").squeeze()
    y_val = pd.read_csv("data/processed/y_val.csv").squeeze()

    # Initialize a simple Random Forest baseline model
    model = RandomForestClassifier(
        n_estimators=100,
        random_state=42,
        class_weight="balanced",
        n_jobs=-1
    )

    # Train
    model.fit(X_train, y_train)

    # Predict and evaluate on validation set
    y_pred = model.predict(X_val)
    y_probs = model.predict_proba(X_val)[:, 1]

    print("Classification report (validation):")
    print(classification_report(y_val, y_pred))

    auc = roc_auc_score(y_val, y_probs)
    print(f"ROC AUC score (validation): {auc:.4f}")

    # Ensure models directory exists
    os.makedirs("models", exist_ok=True)

    # Save the trained model for later use
    joblib.dump(model, "models/baseline_rf.joblib")
    print("[OK] Model saved to models/baseline_rf.joblib")

if __name__ == "__main__":
    main()
