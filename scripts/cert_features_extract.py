import csv
import json
from pathlib import Path
from extract_cert_info import run_apksigner, parse_apksigner_output

def process_apks(apk_dir: Path, output_csv: Path):
    apk_files = list(apk_dir.glob("*.apk"))
    print(f"[INFO] Found {len(apk_files)} APK files in {apk_dir}")

    with open(output_csv, "w", newline="") as csvfile:
        fieldnames = [
            "apk_name",
            "valid_signature",
            "source_stamp",
            "signing_schemes_v1",
            "signing_schemes_v2",
            "signing_schemes_v3",
            "signing_schemes_v4",
            "cert_sha256s"
        ]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        for apk in apk_files:
            print(f"[INFO] Processing {apk.name}")
            output = run_apksigner(apk)
            if output is None:
                print(f"[WARN] Skipping {apk.name} due to apksigner error")
                continue
            cert_info = parse_apksigner_output(output)

            # Flatten signing schemes with default False for missing keys
            schemes = cert_info.get("signing_schemes", {})
            scheme_v1 = schemes.get("v1 scheme", False)
            scheme_v2 = schemes.get("v2 scheme", False)
            scheme_v3 = schemes.get("v3 scheme", False)
            scheme_v4 = schemes.get("v4 scheme", False)

            # Join cert SHA256 digests by ;
            cert_sha256s = ";".join([cert.get("sha256", "") for cert in cert_info.get("certificates", [])])

            writer.writerow({
                "apk_name": apk.name,
                "valid_signature": cert_info.get("valid_signature", False),
                "source_stamp": cert_info.get("source_stamp", ""),
                "signing_schemes_v1": scheme_v1,
                "signing_schemes_v2": scheme_v2,
                "signing_schemes_v3": scheme_v3,
                "signing_schemes_v4": scheme_v4,
                "cert_sha256s": cert_sha256s
            })

    print(f"[OK] Certificate feature extraction complete. Results saved to {output_csv}")

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Extract APK certificate info in batch")
    parser.add_argument("--apk-dir", required=True, help="Path to directory containing APK files")
    parser.add_argument("--output-csv", default="data/processed/cert_features.csv", help="Output CSV path")
    args = parser.parse_args()

    apk_dir_path = Path(args.apk_dir)
    output_csv_path = Path(args.output_csv)
    if not apk_dir_path.exists() or not apk_dir_path.is_dir():
        print(f"[ERROR] APK directory {apk_dir_path} does not exist or is not a directory")
        exit(1)

    process_apks(apk_dir_path, output_csv_path)
