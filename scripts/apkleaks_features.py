import subprocess
import json
from pathlib import Path
import csv

def run_apkleaks(apk_path: Path):
    output_file = Path("tmp_apkleaks.json")
    cmd = ["apkleaks", "-f", str(apk_path.resolve()), "-o", str(output_file.resolve())]
    try:
        subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True)
        with open(output_file, "r", encoding="utf-8") as f:
            return f.read()
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] APKLeaks scan failed on {apk_path}: {e.output}")
        return None
    finally:
        if output_file.exists():
            try:
                output_file.unlink()  # Clean up temp file
            except Exception:
                pass


def parse_apkleaks_output(output: str):
    # APKLeaks outputs JSON lines (each line a JSON event)
    # We'll extract key features like HTTP endpoints, secrets, domains
    endpoints = set()
    secrets = set()
    domains = set()

    for line in output.splitlines():
        try:
            obj = json.loads(line)
            event = obj.get("event", "")
            data = obj.get("data", {})
            if event == "uri":
                uri = data.get("uri", "")
                if uri:
                    endpoints.add(uri)
                    # Extract domain if possible
                    from urllib.parse import urlparse
                    parsed = urlparse(uri)
                    domain = parsed.netloc
                    if domain:
                        domains.add(domain)
            elif event == "secret":
                secret = data.get("secret", "")
                if secret:
                    secrets.add(secret)
        except json.JSONDecodeError:
            continue

    return {
        "num_endpoints": len(endpoints),
        "num_domains": len(domains),
        "num_secrets": len(secrets),
        "sample_endpoint": next(iter(endpoints), ""),
        "sample_secret": next(iter(secrets), "")
    }

def process_apks_with_apkleaks(apk_dir: Path, output_csv: Path):
    apk_files = list(apk_dir.glob("*.apk"))
    print(f"[INFO] Found {len(apk_files)} APK files in {apk_dir}")

    with open(output_csv, "w", newline="", encoding="utf-8") as csvfile:
        fieldnames = [
            "apk_name",
            "num_endpoints",
            "num_domains",
            "num_secrets",
            "sample_endpoint",
            "sample_secret"
        ]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        for apk in apk_files:
            print(f"[INFO] Scanning {apk.name} with APKLeaks")
            output = run_apkleaks(apk)
            if output is None:
                print(f"[WARN] Skipping {apk.name} due to APKLeaks failure")
                continue

            features = parse_apkleaks_output(output)

            writer.writerow({
                "apk_name": apk.name,
                **features
            })

    print(f"[OK] APKLeaks feature extraction complete. Results saved to {output_csv}")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Extract APKLeaks features in batch")
    parser.add_argument("--apk-dir", required=True, help="Path to APK directory")
    parser.add_argument("--output-csv", default="data/processed/apkleaks_features.csv", help="Output CSV")
    args = parser.parse_args()

    apk_dir_path = Path(args.apk_dir)
    output_csv_path = Path(args.output_csv)

    if not apk_dir_path.exists() or not apk_dir_path.is_dir():
        print(f"[ERROR] APK directory {apk_dir_path} does not exist or is not a directory")
        exit(1)

    process_apks_with_apkleaks(apk_dir_path, output_csv_path)
