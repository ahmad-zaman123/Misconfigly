from types import SimpleNamespace

import psycopg
import pytest
from fastapi.testclient import TestClient

from app.main import create_app
from app.store import Store

PASSWORD = "correct-horse-battery"


@pytest.fixture(scope="session")
def database_url(tmp_path_factory):
    import pgserver

    server = pgserver.get_server(tmp_path_factory.mktemp("pg"), cleanup_mode="delete")
    yield server.get_uri()
    server.cleanup()


@pytest.fixture
def store(database_url):
    store = Store(database_url)
    store.init_schema()
    with psycopg.connect(database_url, autocommit=True) as db:
        db.execute("TRUNCATE users, password_reset_tokens, rate_limits CASCADE")
    yield store
    store.close()


def make_settings(database_url, **overrides):
    settings = {
        "database_url": database_url,
        "jwt_secret": "test-jwt-secret-that-is-long-enough-for-hs256",
        "cors_origins": ["http://localhost:5190"],
        "app_url": "http://localhost:5190",
        "google_client_id": "",
        "smtp": None,
        "behind_proxy": False,
    }
    settings.update(overrides)
    return settings


def refuse_google(credential, client_id):
    raise AssertionError("Tests never call Google")


class FakeGoogle:
    """Stands in for Google's token check. Each credential signs in as the email it names, unless set in `claims`."""

    def __init__(self):
        self.claims = {}

    def __call__(self, credential, client_id):
        if credential == "forged":
            raise ValueError("Invalid Google token")
        return self.claims.get(credential, {"email": credential, "email_verified": True})


class FakeMailer:
    """Keeps emails instead of sending them. Set `error` to make sending fail."""

    def __init__(self):
        self.sent = []
        self.error = None

    def __call__(self, to, subject, heading, text, action_label, action_url, note):
        if self.error:
            raise self.error
        self.sent.append(SimpleNamespace(to=to, subject=subject, text=text, url=action_url))


@pytest.fixture
def mailer():
    return FakeMailer()


@pytest.fixture
def build(store, database_url):
    """Builds a TestClient. Pass setting overrides, send_email, verify_google and scan_target."""

    def _build(send_email=None, verify_google=None, scan_target=None, **overrides):
        app = create_app(
            make_settings(database_url, **overrides),
            store=store,
            send_email=send_email,
            verify_google=verify_google or refuse_google,
            scan_target=scan_target or (lambda user: None),
        )
        return TestClient(app)

    return _build


@pytest.fixture
def client(build):
    return build()


def bearer(token):
    return {"Authorization": "Bearer " + token}


def sign_up(client, email="sara@example.com", password=PASSWORD):
    response = client.post("/api/auth/register", json={"email": email, "password": password})
    assert response.status_code == 201, response.text
    return response.json()
