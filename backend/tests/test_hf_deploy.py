"""The Hugging Face deploy script, run against a fake API (no network, no account)."""

import importlib.util
from pathlib import Path
from types import SimpleNamespace

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "deploy" / "huggingface" / "deploy.py"
spec = importlib.util.spec_from_file_location("hf_deploy", SCRIPT)
hf = importlib.util.module_from_spec(spec)
spec.loader.exec_module(hf)


class FakeApi:
    def __init__(self, exists=False, stages=("BUILDING", "BUILDING", "RUNNING"), user="asmit"):
        self.exists, self.stages, self.user = exists, list(stages), user
        self.calls, self.secrets, self.uploaded = [], {}, None

    def whoami(self):
        if self.user is None:
            raise RuntimeError("401")
        return {"name": self.user}

    def repo_exists(self, repo_id, repo_type=None):
        return self.exists

    def create_repo(self, repo_id, **kw):
        self.calls.append(("create_repo", repo_id, kw))

    def add_space_secret(self, repo_id, key, value, **kw):
        self.calls.append(("secret", key))
        self.secrets[key] = value

    def upload_folder(self, repo_id, folder_path, **kw):
        self.calls.append(("upload", repo_id))
        root = Path(folder_path)
        self.uploaded = {str(p.relative_to(root)).replace("\\", "/") for p in root.rglob("*") if p.is_file()}

    def get_space_runtime(self, repo_id):
        return SimpleNamespace(stage=self.stages.pop(0) if len(self.stages) > 1 else self.stages[0])


def run(api, **kw):
    return hf.deploy(api, "threatlens-ai", sleep=lambda s: None, log=lambda *a: None, poll_seconds=0, **kw)


def test_first_deploy_creates_the_space_sets_secrets_and_uploads():
    api = FakeApi()
    result = run(api)
    assert result["repo_id"] == "asmit/threatlens-ai"
    assert result["url"] == "https://asmit-threatlens-ai.hf.space"
    kinds = [c[0] for c in api.calls]
    assert kinds.index("create_repo") < kinds.index("secret") < kinds.index("upload")  # secrets before the first build
    create = next(c for c in api.calls if c[0] == "create_repo")
    assert create[2]["space_sdk"] == "docker" and create[2]["private"] is False
    assert set(api.secrets) == {"JWT_SECRET_KEY", "DEV_LOGIN_PASSWORD"}
    assert len(api.secrets["JWT_SECRET_KEY"]) >= 32
    assert result["password"] == api.secrets["DEV_LOGIN_PASSWORD"] and len(result["password"]) >= 12


def test_the_uploaded_folder_is_complete_and_clean():
    api = FakeApi()
    run(api)
    files = api.uploaded
    assert {"Dockerfile", "README.md", "backend/requirements.txt", "backend/app/main.py"} <= files
    assert "backend/app/ml/models/artifacts/detector.txt" in files
    assert "demo/samples/trojan_downloader.bin" in files
    assert "frontend/package.json" in files and "frontend/src/main.tsx" in files
    assert not [
        f for f in files
        if any(bad in f for bad in ("node_modules", "__pycache__", ".cache", "/var/", ".env"))
        or f.endswith((".npz", ".log"))
    ]
    assert not [f for f in files if f.startswith("backend/tests")]


def test_redeploying_keeps_the_existing_secrets():
    api = FakeApi(exists=True)
    result = run(api)
    assert api.secrets == {} and result["password"] is None
    assert [c[0] for c in api.calls].count("upload") == 1


def test_reset_secrets_replaces_them_and_accepts_a_chosen_password():
    api = FakeApi(exists=True)
    result = run(api, reset_secrets=True, password="my-own-demo-password")
    assert api.secrets["DEV_LOGIN_PASSWORD"] == "my-own-demo-password" == result["password"]


def test_short_passwords_are_refused_before_anything_is_changed():
    api = FakeApi()
    with pytest.raises(hf.DeployError, match="at least 12"):
        run(api, password="short")
    assert not [c for c in api.calls if c[0] in ("secret", "upload")]


def test_a_bad_token_gives_actionable_guidance():
    with pytest.raises(hf.DeployError, match="HF_TOKEN"):
        run(FakeApi(user=None))


@pytest.mark.parametrize("stage", ["BUILD_ERROR", "RUNTIME_ERROR", "CONFIG_ERROR"])
def test_build_failures_point_at_the_logs(stage):
    with pytest.raises(hf.DeployError, match="logs=build"):
        run(FakeApi(stages=("BUILDING", stage)))


def test_it_gives_up_with_a_clear_message_if_the_build_never_finishes():
    with pytest.raises(hf.DeployError, match="Still"):
        hf.deploy(FakeApi(stages=("BUILDING",)), "threatlens-ai", wait_minutes=0.0001,
                  sleep=lambda s: None, log=lambda *a: None, poll_seconds=0)


@pytest.mark.parametrize(
    "repo,expected",
    [
        ("Asmit/ThreatLens_AI", "https://asmit-threatlens-ai.hf.space"),
        ("a.b/c.d", "https://a-b-c-d.hf.space"),
    ],
)
def test_space_url_follows_hugging_faces_naming(repo, expected):
    assert hf.space_url(repo) == expected
