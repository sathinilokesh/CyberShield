import pandas as pd

def merge_features(drebin_csv, cert_csv, apkleaks_csv, output_csv):
    drebin_df = pd.read_csv(drebin_csv)
    cert_df = pd.read_csv(cert_csv)
    apkleaks_df = pd.read_csv(apkleaks_csv)

    # Normalize apk_name column in drebin_df if needed
    if "apk_name" not in drebin_df.columns:
        print("[WARN] No apk_name column in drebin dataset. Add or match on hash/key")
        # Assuming you have a way to join on hash or add apk_name later
        # For now, left join might not be reliable
        merged_df = drebin_df
    else:
        merged_df = pd.merge(drebin_df, cert_df, how="left", on="apk_name")
        merged_df = pd.merge(merged_df, apkleaks_df, how="left", on="apk_name")

    # Fill NaNs for cert/apkleaks features with safe defaults
    merged_df["valid_signature"].fillna(False, inplace=True)
    merged_df["num_endpoints"].fillna(0, inplace=True)
    merged_df["num_domains"].fillna(0, inplace=True)
    merged_df["num_secrets"].fillna(0, inplace=True)

    # Save merged features for training
    merged_df.to_csv(output_csv, index=False)
    print(f"[OK] Saved merged dataset to {output_csv}")

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Merge multiple feature sets into one CSV")
    parser.add_argument("--drebin", required=True, help="Path to Drebin features CSV")
    parser.add_argument("--cert", required=True, help="Path to certificate features CSV")
    parser.add_argument("--apkleaks", required=True, help="Path to APKLeaks features CSV")
    parser.add_argument("--output", default="data/processed/merged_features.csv", help="Output merged CSV path")

    args = parser.parse_args()

    merge_features(args.drebin, args.cert, args.apkleaks, args.output)
