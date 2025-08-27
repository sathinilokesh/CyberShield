import subprocess
import json
from pathlib import Path
import re

def run_apksigner(apk_path: Path):
    cmd = ["apksigner.bat", "verify", "--verbose", "--print-certs", str(apk_path)]
    try:
        output = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True)
        return output
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Failed to run apksigner on {apk_path}: {e.output}")
        return None

def parse_apksigner_output(output: str):
    certs_info = []

    # Regex patterns
    cert_pattern = re.compile(r"Signer #\d certificate SHA-256 digest: ([a-fA-F0-9:]+)")
    dn_pattern = re.compile(r"Signer #\d certificate DN: (.+)")
    scheme_pattern = re.compile(r"Verified using (v\d(\.\d+)? scheme).*: (true|false)")
    sourcestamp_pattern = re.compile(r"Source Stamp Signer certificate SHA-256 digest: ([a-fA-F0-9:]+)")
    sourcestamp_verified_pattern = re.compile(r"Verified for SourceStamp: (true|false)")

    # Extract certificates
    certs = cert_pattern.findall(output)
    dns = dn_pattern.findall(output)
    for idx, cert in enumerate(certs):
        cert_digest = cert.replace(":", "").lower()
        certs_info.append({
            "subject_dn": dns[idx] if idx < len(dns) else None,
            "sha256": cert_digest
        })

    # Extract signing schemes
    schemes = {}
    for match in scheme_pattern.findall(output):
        scheme_name, _, valid = match
        schemes[scheme_name] = (valid.lower() == "true")

    # Extract SourceStamp
    sourcestamp = sourcestamp_pattern.search(output)
    sourcestamp_digest = sourcestamp.group(1).replace(":", "").lower() if sourcestamp else None

    sourcestamp_verified = False
    match = sourcestamp_verified_pattern.search(output)
    if match:
        sourcestamp_verified = (match.group(1).lower() == "true")

    # Determine overall validity
    valid_signature = any(schemes.values())

    return {
        "valid_signature": valid_signature,
        "signing_schemes": schemes,
        "certificates": certs_info,
        "source_stamp": sourcestamp_digest,
        "from_play_store": sourcestamp_verified
    }

def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("apk_path", type=str, help="Path to the APK file")
    args = parser.parse_args()

    apk_path = Path(args.apk_path)
    if not apk_path.exists():
        print(f"[ERROR] APK file not found: {apk_path}")
        return

    output = run_apksigner(apk_path)
    if output is None:
        return

    cert_info = parse_apksigner_output(output)
    print(json.dumps(cert_info, indent=2))

if __name__ == "__main__":
    main()
