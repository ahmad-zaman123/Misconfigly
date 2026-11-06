import hashlib
import hmac
import os
import secrets
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

import psycopg
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool

# Longer than a session lasts, so nobody loses a demo they are still using.
DEMO_LIFETIME = timedelta(days=2)
# Old demos are removed in batches each time a new one starts, so no single request does too much.
DEMO_PURGE_BATCH = 50
# Short, because anyone who sees the link in the inbox can use it.
RESET_TOKEN_LIFETIME = timedelta(minutes=15)
POOL_OPEN_TIMEOUT = 10

USER_COLUMNS = "id, email, is_demo, email_verified, session_version, password_hash IS NOT NULL AS has_password, created_at"

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT,
    is_demo BOOLEAN NOT NULL DEFAULT false,
    email_verified BOOLEAN NOT NULL DEFAULT false,
    -- Every session carries this number. Raising it ends all sessions started before.
    session_version INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS users_demo_idx ON users (created_at) WHERE is_demo;
CREATE TABLE IF NOT EXISTS password_reset_tokens (
    token_hash TEXT PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at TIMESTAMPTZ NOT NULL
);
CREATE TABLE IF NOT EXISTS rate_limits (
    key TEXT PRIMARY KEY,
    hits INTEGER NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL
);
"""


def hash_password(password):
    salt = os.urandom(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)
    return f"{salt.hex()}:{digest.hex()}"


def verify_password(password, stored):
    salt, digest = stored.split(":")
    candidate = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=2**14, r=8, p=1)
    return hmac.compare_digest(candidate.hex(), digest)


def _token_hash(token):
    return hashlib.sha256(token.encode()).hexdigest()


# Checked when the email is unknown, so the response time doesn't reveal which accounts exist.
_DUMMY_HASH = hash_password(uuid.uuid4().hex)


class Store:
    def __init__(self, database_url):
        self.database_url = database_url
        self._pool = None

    def _get_pool(self):
        if self._pool is None:
            pool = ConnectionPool(
                self.database_url,
                open=False,
                min_size=1,
                max_size=5,
                # Neon closes idle connections when it scales to zero.
                check=ConnectionPool.check_connection,
                # Poolers like PgBouncer share server connections, so prepared statements are off.
                kwargs={"row_factory": dict_row, "prepare_threshold": None},
            )
            try:
                pool.open(wait=True, timeout=POOL_OPEN_TIMEOUT)
            except Exception:
                # A pool that failed to open stays closed, so let the next request try again.
                pool.close()
                raise
            self._pool = pool
        return self._pool

    def close(self):
        if self._pool is not None:
            self._pool.close()
            self._pool = None

    def init_schema(self):
        with psycopg.connect(self.database_url, autocommit=True) as db:
            db.execute(SCHEMA)

    @contextmanager
    def _connect(self):
        with self._get_pool().connection() as db:
            yield db

    # Users

    @staticmethod
    def _insert_user(db, email, password_hash=None, is_demo=False, email_verified=False):
        """The new user, or None if the email is taken."""
        return db.execute(
            "INSERT INTO users (id, email, password_hash, is_demo, email_verified) VALUES (%s, %s, %s, %s, %s) "
            f"ON CONFLICT (email) DO NOTHING RETURNING {USER_COLUMNS}",
            (uuid.uuid4(), email, password_hash, is_demo, email_verified),
        ).fetchone()

    def create_user(self, email, password):
        password_hash = hash_password(password)
        with self._connect() as db:
            return self._insert_user(db, email.lower(), password_hash)

    def authenticate(self, email, password):
        with self._connect() as db:
            user = db.execute(
                f"SELECT {USER_COLUMNS}, password_hash FROM users WHERE email = %s", (email.lower(),)
            ).fetchone()
        stored = user["password_hash"] if user and user["password_hash"] else _DUMMY_HASH
        if not verify_password(password, stored) or not user or not user["password_hash"]:
            return None
        return {key: value for key, value in user.items() if key != "password_hash"}

    def get_user(self, user_id):
        with self._connect() as db:
            return db.execute(f"SELECT {USER_COLUMNS} FROM users WHERE id = %s", (user_id,)).fetchone()

    @staticmethod
    def _end_sessions(db, user_id):
        """Every session started so far stops working."""
        db.execute("UPDATE users SET session_version = session_version + 1 WHERE id = %s", (user_id,))

    def set_password(self, user_id, password):
        with self._connect() as db:
            db.execute(
                "UPDATE users SET password_hash = %s WHERE id = %s AND NOT is_demo", (hash_password(password), user_id)
            )
            self._end_sessions(db, user_id)

    def find_or_create_verified_user(self, email):
        """The account for an email Google has confirmed, made without a password if it's new. None for demos."""
        email = email.lower()
        with self._connect() as db:
            created = self._insert_user(db, email, email_verified=True)
            if created:
                return created
            existing = db.execute(
                "SELECT id, is_demo, email_verified, password_hash FROM users WHERE email = %s FOR UPDATE", (email,)
            ).fetchone()
            if existing["is_demo"]:
                return None
            if not existing["email_verified"]:
                # Signing up doesn't prove who owns an email, so a password set before now may be a stranger's.
                db.execute("UPDATE users SET email_verified = true, password_hash = NULL WHERE id = %s", (existing["id"],))
                if existing["password_hash"]:
                    self._end_sessions(db, existing["id"])
            return db.execute(f"SELECT {USER_COLUMNS} FROM users WHERE id = %s", (existing["id"],)).fetchone()

    def create_reset_token(self, email):
        """A new single-use reset token, or None if there's no such account or it's a demo."""
        token = secrets.token_urlsafe(32)
        with self._connect() as db:
            user = db.execute("SELECT id FROM users WHERE email = %s AND NOT is_demo", (email.lower(),)).fetchone()
            if user is None:
                return None
            db.execute("DELETE FROM password_reset_tokens WHERE user_id = %s OR expires_at < now()", (user["id"],))
            # Only a hash is stored, so reading the database doesn't give anyone a working link.
            db.execute(
                "INSERT INTO password_reset_tokens (token_hash, user_id, expires_at) VALUES (%s, %s, %s)",
                (_token_hash(token), user["id"], datetime.now(timezone.utc) + RESET_TOKEN_LIFETIME),
            )
        return token

    def reset_password(self, token, password):
        """Use up a reset token to set a new password. False if it's invalid or expired."""
        password_hash = hash_password(password)
        with self._connect() as db:
            row = db.execute(
                "DELETE FROM password_reset_tokens WHERE token_hash = %s RETURNING user_id, expires_at > now() AS valid",
                (_token_hash(token),),
            ).fetchone()
            if row is None or not row["valid"]:
                return False
            # The link reached this inbox, which proves who owns the email.
            db.execute(
                "UPDATE users SET password_hash = %s, email_verified = true WHERE id = %s", (password_hash, row["user_id"])
            )
            self._end_sessions(db, row["user_id"])
        return True

    # Demos

    @staticmethod
    def _purge_demos(db):
        db.execute(
            "DELETE FROM users WHERE id IN (SELECT id FROM users WHERE is_demo AND created_at < %s "
            "ORDER BY created_at LIMIT %s)",
            (datetime.now(timezone.utc) - DEMO_LIFETIME, DEMO_PURGE_BATCH),
        )

    def create_demo_user(self):
        """A private demo account that can't be signed into with a password. Old demos are removed first."""
        with self._connect() as db:
            self._purge_demos(db)
            db.execute("DELETE FROM rate_limits WHERE expires_at < now()")
            return self._insert_user(db, f"demo-{uuid.uuid4().hex[:12]}@demo.misconfigly.app", is_demo=True)

    # Rate limits

    def hit_rate_limit(self, key, limit, window):
        """Count one hit. Returns the seconds to wait if the limit is exceeded, otherwise None."""
        with self._connect() as db:
            row = db.execute(
                "INSERT INTO rate_limits AS r (key, hits, expires_at) VALUES (%(key)s, 1, now() + %(window)s) "
                "ON CONFLICT (key) DO UPDATE SET "
                "hits = CASE WHEN r.expires_at <= now() THEN 1 ELSE r.hits + 1 END, "
                "expires_at = CASE WHEN r.expires_at <= now() THEN EXCLUDED.expires_at ELSE r.expires_at END "
                "RETURNING hits, EXTRACT(EPOCH FROM expires_at - now()) AS wait",
                {"key": key, "window": window},
            ).fetchone()
        return max(1, int(row["wait"])) if row["hits"] > limit else None
