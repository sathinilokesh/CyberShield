import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, roc_auc_score
import joblib

def main():
    merged_csv = "data/processed/merged_features.csv"

    df = pd.read_csv(merged_csv)
    # Extract label column (adjust column name as needed)
    y = df["label"]
    X = df.drop(columns=["label", "apk_name"])

    model = RandomForestClassifier(
        n_estimators=150,
        random_state=42,
        class_weight="balanced",
        n_jobs=-1
    )

    # Split train/val manually or use same split indices as earlier
    from sklearn.model_selection import train_test_split
    X_train, X_val, y_train, y_val = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    model.fit(X_train, y_train)

    y_pred = model.predict(X_val)
    y_probs = model.predict_proba(X_val)[:, 1]

    print("Classification report (validation):")
    print(classification_report(y_val, y_pred))
    print(f"ROC AUC (validation): {roc_auc_score(y_val, y_probs):.4f}")

    joblib.dump(model, "models/enhanced_rf.joblib")
    print("[OK] Enhanced model saved to models/enhanced_rf.joblib")

if __name__ == "__main__":
    main()
