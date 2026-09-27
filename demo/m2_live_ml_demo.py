"""Milestone 2 live demo: feed a real malware sample straight through the API.

Downloads one known-malicious and one known-benign Windows PE from
DikeDataset (MIT-licensed, github.com/iosifache/DikeDataset) directly into
memory and POSTs each to the running ThreatLens API. **The raw file is never
written to disk** - it exists only in this process's memory for the length of
the HTTP request, same as the training fetcher in
backend/app/ml/training/fetch_dikedataset.py.

Run with the backend up on localhost:8000:

    python demo/m2_live_ml_demo.py

Prints the fused verdict for each sample so you can narrate live, then check
the same results in the browser (Reports / Threat Monitor / Alerts).
"""

import io
import sys

import requests

API = "http://127.0.0.1:8000/api/v1"
RAW = "https://raw.githubusercontent.com/iosifache/DikeDataset/main/files"

# A real malicious PE the rule engine has *no* YARA/string signal for
# (packed, no readable strings) - the ML model is the only thing that
# catches it. Hash is public, from the DikeDataset malware set.
MALWARE_HASH = "936c36121f73b175ef68231ee234c55103c93d7dfeb75dd8fdc3480aa5c08aeb"
# A real benign PE, for the "engines agree, it's clean" moment.
BENIGN_HASH = "ca6710ac624c4badd89606d2d46270b68a494b9778a109477955f6403d77493e"


def login(email: str, password: str = "x") -> str:
    r = requests.post(f"{API}/auth/login", json={"email": email, "password": password}, timeout=10)
    r.raise_for_status()
    return r.json()["access_token"]


def fetch(kind: str, sha256: str) -> bytes:
    r = requests.get(f"{RAW}/{kind}/{sha256}.exe", timeout=30)
    r.raise_for_status()
    return r.content


def upload(token: str, filename: str, data: bytes) -> dict:
    r = requests.post(
        f"{API}/files/upload",
        headers={"Authorization": f"Bearer {token}"},
        files={"file": (filename, io.BytesIO(data), "application/octet-stream")},
        timeout=30,
    )
    r.raise_for_status()
    return r.json()


def show(label: str, result: dict) -> None:
    v = result["verdict"]
    ml = result["ml"]
    print(f"\n=== {label} ===")
    print(f"  file           : {result['object_path']}")
    print(f"  sha256         : {result['hashes']['sha256']}")
    print(f"  static risk    : {result['risk']['score']}/100 ({result['risk']['level']})")
    print(f"  ML probability : {ml['malware_probability']:.1%}  (model {ml['model_versions'].get('detector')})")
    print(f"  FUSED VERDICT  : {v['label'].upper()}  {v['score']}/100  [{v['agreement']}]")
    print(f"  classification : {v['classification']}")
    print(f"  action         : {v['recommended_action']}")


def main() -> None:
    email = sys.argv[1] if len(sys.argv) > 1 else "analyst@local"
    print(f"Signing in as {email} ...")
    token = login(email)

    print("Fetching a real malicious PE (in memory only, never written to disk) ...")
    show("Known-malicious sample (ML should catch this)", upload(token, "sample_a.exe", fetch("malware", MALWARE_HASH)))

    print("\nFetching a real benign PE ...")
    show("Known-benign sample (both engines should agree)", upload(token, "sample_b.exe", fetch("benign", BENIGN_HASH)))

    print("\nDone. Switch to the browser: Reports (latest), Threat Monitor, and Alerts should all reflect these.")


if __name__ == "__main__":
    main()
