from datetime import datetime, timedelta, timezone

import jwt
import psycopg

from app.main import RATE_LIMITS, RESET_INVALID, RESET_SENT
from app.store import DEMO_LIFETIME, DEMO_PURGE_BATCH

from .conftest import PASSWORD, FakeGoogle, bearer, sign_up

NEW_PASSWORD = "a-brand-new-password"


def reset_token(mailer):
    return mailer.sent[-1].url.split("token=")[1]


def set_created(database_url, user_id, when):
    with psycopg.connect(database_url, autocommit=True) as db:
        db.execute("UPDATE users SET created_at = %s WHERE id = %s", (when, user_id))


# Sign-up and sign-in


def test_sign_up_signs_in(client):
    session = sign_up(client, email="Sara@Example.com")
    assert session["user"]["email"] == "sara@example.com"
    assert session["user"]["is_demo"] is False
    me = client.get("/api/me", headers=bearer(session["token"]))
    assert me.status_code == 200
    assert me.json()["email"] == "sara@example.com"


def test_an_email_can_only_sign_up_once(client):
    sign_up(client)
    response = client.post("/api/auth/register", json={"email": "SARA@example.com", "password": PASSWORD})
    assert response.status_code == 409


def test_short_passwords_and_bad_emails_are_refused(client):
    assert client.post("/api/auth/register", json={"email": "sara@example.com", "password": "short"}).status_code == 422
    assert client.post("/api/auth/register", json={"email": "not-an-email", "password": PASSWORD}).status_code == 422


def test_errors_never_echo_the_password(client):
    response = client.post("/api/auth/register", json={"email": "sara@example.com", "password": "abc\x00"})
    assert response.status_code == 422
    assert "abc" not in response.text


def test_sign_in(client):
    sign_up(client)
    response = client.post("/api/auth/login", json={"email": "SARA@example.com", "password": PASSWORD})
    assert response.status_code == 200
    assert client.get("/api/me", headers=bearer(response.json()["token"])).status_code == 200


def test_wrong_password_and_unknown_email_get_the_same_reply(client):
    sign_up(client)
    wrong = client.post("/api/auth/login", json={"email": "sara@example.com", "password": "nope-nope-nope"})
    unknown = client.post("/api/auth/login", json={"email": "who@example.com", "password": "nope-nope-nope"})
    assert wrong.status_code == unknown.status_code == 401
    assert wrong.json() == unknown.json()


def test_passwords_are_stored_hashed(client, database_url):
    sign_up(client)
    with psycopg.connect(database_url) as db:
        stored = db.execute("SELECT password_hash FROM users").fetchone()[0]
    assert PASSWORD not in stored
    assert ":" in stored


def test_bad_or_expired_tokens_are_refused(client):
    session = sign_up(client)
    claims = jwt.decode(session["token"], options={"verify_signature": False})
    expired = jwt.encode(
        {"sub": claims["sub"], "iat": 0, "exp": datetime.now(timezone.utc) - timedelta(minutes=1)},
        "test-jwt-secret-that-is-long-enough-for-hs256",
        algorithm="HS256",
    )
    forged = jwt.encode({"sub": claims["sub"], "iat": claims["iat"]}, "some-other-secret-that-is-long-enough", algorithm="HS256")
    for headers in ({}, {"Authorization": "Basic abc"}, bearer("garbage"), bearer(expired), bearer(forged)):
        assert client.get("/api/me", headers=headers).status_code == 401


def test_sign_in_is_rate_limited(client):
    limit = RATE_LIMITS["login"][0]
    for _ in range(limit):
        client.post("/api/auth/login", json={"email": "sara@example.com", "password": "nope-nope-nope"})
    blocked = client.post("/api/auth/login", json={"email": "sara@example.com", "password": "nope-nope-nope"})
    assert blocked.status_code == 429
    assert int(blocked.headers["Retry-After"]) >= 1


# Private demos


def test_demo_gets_a_private_account(client):
    response = client.post("/api/auth/demo")
    assert response.status_code == 201
    user = response.json()["user"]
    assert user["is_demo"] is True
    assert user["has_password"] is False
    assert user["email"].endswith("@demo.misconfigly.app")
    assert client.get("/api/me", headers=bearer(response.json()["token"])).json()["id"] == user["id"]
    assert client.post("/api/auth/demo").json()["user"]["id"] != user["id"]


def test_demo_is_limited_per_address(build):
    client = build()
    for _ in range(RATE_LIMITS["demo"][0]):
        assert client.post("/api/auth/demo").status_code == 201
    blocked = client.post("/api/auth/demo")
    assert blocked.status_code == 429
    assert blocked.json()["detail"] == RATE_LIMITS["demo"][2]


def test_demo_limit_uses_the_proxy_address_only_behind_a_proxy(build):
    trusting = build(behind_proxy=True)
    for _ in range(RATE_LIMITS["demo"][0]):
        trusting.post("/api/auth/demo", headers={"X-Real-IP": "203.0.113.1"})
    assert trusting.post("/api/auth/demo", headers={"X-Real-IP": "203.0.113.1"}).status_code == 429
    assert trusting.post("/api/auth/demo", headers={"X-Real-IP": "203.0.113.2"}).status_code == 201


def test_demo_has_a_daily_total(client, store):
    limit = RATE_LIMITS["demo_all"][0]
    client.post("/api/auth/demo")
    with psycopg.connect(store.database_url, autocommit=True) as db:
        db.execute("UPDATE rate_limits SET hits = %s WHERE key = 'demo_all:all'", (limit,))
    blocked = client.post("/api/auth/demo")
    assert blocked.status_code == 429
    assert blocked.json()["detail"] == RATE_LIMITS["demo_all"][2]


def test_old_demos_are_removed_when_a_new_one_starts(client, database_url):
    old = client.post("/api/auth/demo").json()
    real = sign_up(client)
    set_created(database_url, old["user"]["id"], datetime.now(timezone.utc) - DEMO_LIFETIME - timedelta(minutes=1))
    set_created(database_url, real["user"]["id"], datetime.now(timezone.utc) - timedelta(days=30))
    client.post("/api/auth/demo")
    assert client.get("/api/me", headers=bearer(old["token"])).status_code == 401
    assert client.get("/api/me", headers=bearer(real["token"])).status_code == 200


def test_old_demos_are_removed_in_batches(client, store, database_url):
    for _ in range(DEMO_PURGE_BATCH + 3):
        store.create_demo_user()
    with psycopg.connect(database_url, autocommit=True) as db:
        db.execute("UPDATE users SET created_at = %s", (datetime.now(timezone.utc) - DEMO_LIFETIME - timedelta(hours=1),))
    client.post("/api/auth/demo")
    with psycopg.connect(database_url) as db:
        left = db.execute("SELECT count(*) FROM users WHERE is_demo").fetchone()[0]
    assert left == 4  # three old ones wait for the next demo, plus the new one


def test_demo_cannot_set_a_password(client):
    token = client.post("/api/auth/demo").json()["token"]
    response = client.post("/api/me/password", json={"new_password": NEW_PASSWORD}, headers=bearer(token))
    assert response.status_code == 403


def test_demo_gets_no_reset_email(build, mailer):
    client = build(send_email=mailer)
    email = client.post("/api/auth/demo").json()["user"]["email"]
    assert client.post("/api/password/forgot", json={"email": email}).json() == {"detail": RESET_SENT}
    assert mailer.sent == []


def test_demo_cannot_sign_in_with_google(build):
    google = FakeGoogle()
    client = build(google_client_id="client-id", verify_google=google)
    email = client.post("/api/auth/demo").json()["user"]["email"]
    assert client.post("/api/auth/google", json={"credential": email}).status_code == 403


# Google sign-in


def test_google_is_off_without_a_client_id(client):
    assert client.get("/api/auth/options").json() == {"password_reset": False, "google": False}
    assert client.post("/api/auth/google", json={"credential": "sara@example.com"}).status_code == 404


def test_google_creates_an_account_without_a_password(build):
    client = build(google_client_id="client-id", verify_google=FakeGoogle())
    assert client.get("/api/auth/options").json()["google"] is True
    response = client.post("/api/auth/google", json={"credential": "Omar@Example.com"})
    assert response.status_code == 200
    assert response.json()["user"] == {**response.json()["user"], "email": "omar@example.com", "has_password": False}
    again = client.post("/api/auth/google", json={"credential": "omar@example.com"})
    assert again.json()["user"]["id"] == response.json()["user"]["id"]


def test_google_refuses_forged_and_unverified_tokens(build):
    google = FakeGoogle()
    google.claims["unverified"] = {"email": "x@example.com", "email_verified": False}
    google.claims["no-email"] = {"email_verified": True}
    client = build(google_client_id="client-id", verify_google=google)
    for credential in ("forged", "unverified", "no-email"):
        assert client.post("/api/auth/google", json={"credential": credential}).status_code == 401


def test_google_takes_over_an_unverified_sign_up(build):
    client = build(google_client_id="client-id", verify_google=FakeGoogle())
    squatter = sign_up(client, email="omar@example.com")
    owner = client.post("/api/auth/google", json={"credential": "omar@example.com"}).json()
    assert owner["user"]["id"] == squatter["user"]["id"]
    assert owner["user"]["has_password"] is False
    # Whoever signed up first can no longer get in with their password or session.
    assert client.post("/api/auth/login", json={"email": "omar@example.com", "password": PASSWORD}).status_code == 401
    assert client.get("/api/me", headers=bearer(squatter["token"])).status_code == 401
    assert client.get("/api/me", headers=bearer(owner["token"])).status_code == 200


# Passwords


def test_changing_the_password_ends_other_sessions(client):
    first = sign_up(client)
    response = client.post(
        "/api/me/password",
        json={"current_password": PASSWORD, "new_password": NEW_PASSWORD},
        headers=bearer(first["token"]),
    )
    assert response.status_code == 200
    assert client.get("/api/me", headers=bearer(first["token"])).status_code == 401
    assert client.get("/api/me", headers=bearer(response.json()["token"])).status_code == 200
    login = client.post("/api/auth/login", json={"email": "sara@example.com", "password": NEW_PASSWORD})
    assert login.status_code == 200


def test_changing_the_password_needs_the_current_one(client):
    token = sign_up(client)["token"]
    response = client.post(
        "/api/me/password", json={"current_password": "wrong-password", "new_password": NEW_PASSWORD}, headers=bearer(token)
    )
    assert response.status_code == 400


def test_google_accounts_can_add_a_password(build):
    client = build(google_client_id="client-id", verify_google=FakeGoogle())
    token = client.post("/api/auth/google", json={"credential": "omar@example.com"}).json()["token"]
    response = client.post("/api/me/password", json={"new_password": NEW_PASSWORD}, headers=bearer(token))
    assert response.status_code == 200
    assert response.json()["user"]["has_password"] is True


def test_reset_is_off_without_email(client):
    assert client.post("/api/password/forgot", json={"email": "sara@example.com"}).status_code == 503


def test_reset_by_email(build, mailer):
    client = build(send_email=mailer)
    old = sign_up(client)
    assert client.get("/api/auth/options").json()["password_reset"] is True
    assert client.post("/api/password/forgot", json={"email": "SARA@example.com"}).json() == {"detail": RESET_SENT}
    assert mailer.sent[0].to == "sara@example.com"
    assert mailer.sent[0].url.startswith("http://localhost:5190/reset-password?token=")

    token = reset_token(mailer)
    assert client.post("/api/password/reset", json={"token": token, "new_password": NEW_PASSWORD}).status_code == 200
    assert client.post("/api/auth/login", json={"email": "sara@example.com", "password": NEW_PASSWORD}).status_code == 200
    assert client.get("/api/me", headers=bearer(old["token"])).status_code == 401
    # Each link works once.
    again = client.post("/api/password/reset", json={"token": token, "new_password": "yet-another-password"})
    assert again.json()["detail"] == RESET_INVALID


def test_unknown_emails_get_the_same_reply_and_no_email(build, mailer):
    client = build(send_email=mailer)
    assert client.post("/api/password/forgot", json={"email": "nobody@example.com"}).json() == {"detail": RESET_SENT}
    assert mailer.sent == []


def test_expired_reset_links_fail(build, mailer, database_url):
    client = build(send_email=mailer)
    sign_up(client)
    client.post("/api/password/forgot", json={"email": "sara@example.com"})
    with psycopg.connect(database_url, autocommit=True) as db:
        db.execute("UPDATE password_reset_tokens SET expires_at = now() - interval '1 minute'")
    response = client.post("/api/password/reset", json={"token": reset_token(mailer), "new_password": NEW_PASSWORD})
    assert response.status_code == 400


def test_reset_emails_per_address_are_capped_silently(build, mailer):
    client = build(send_email=mailer)
    sign_up(client)
    for _ in range(RATE_LIMITS["reset_email"][0] + 2):
        assert client.post("/api/password/forgot", json={"email": "sara@example.com"}).json() == {"detail": RESET_SENT}
    assert len(mailer.sent) == RATE_LIMITS["reset_email"][0]


def test_a_failed_send_still_gives_the_same_reply(build, mailer, caplog):
    mailer.error = OSError("SMTP down")
    client = build(send_email=mailer)
    sign_up(client)
    assert client.post("/api/password/forgot", json={"email": "sara@example.com"}).json() == {"detail": RESET_SENT}
    assert "Could not send a password reset email" in caplog.text


def test_health(client):
    assert client.get("/api/health").json() == {"ok": True}
