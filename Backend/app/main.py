import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Annotated, Literal

import jwt
from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import AfterValidator, BaseModel, EmailStr, Field

from .aws import AwsAccess, ConnectionFailed, new_external_id, parse_role_arn
from .config import load_settings
from .mailer import smtp_sender
from .scanner import CHECKS, run_scan
from .scanner.scoring import summarize
from .scans import ScanTarget, catalog, grouped_checks, scan_view
from .store import Store

logger = logging.getLogger(__name__)

TOKEN_LIFETIME = timedelta(hours=8)
BUSY = "Too many requests. Please try again in a little while."
RESET_SENT = "If that email has an account, we've sent a reset link."
RESET_INVALID = "This reset link is invalid or has expired."
NOT_SIGNED_IN = "Not signed in"

# Name: (allowed hits, window, message). Kept in Postgres because serverless instances share no memory.
RATE_LIMITS = {
    "login": (20, timedelta(minutes=15), "Too many sign-in attempts. Please try again in a few minutes."),
    "register": (10, timedelta(hours=1), BUSY),
    "demo": (10, timedelta(hours=1), "Too many demos started from here. Please try again in an hour."),
    "demo_all": (500, timedelta(days=1), "The demo is full for today. Please try again tomorrow."),
    "password_change": (10, timedelta(minutes=15), "Too many attempts. Please try again in a few minutes."),
    "reset_ip": (10, timedelta(hours=1), BUSY),
    # Over this one nothing is sent, but the reply doesn't change, so it can't reveal accounts.
    "reset_email": (3, timedelta(hours=1), None),
    "reset_all": (200, timedelta(days=1), "Password reset is busy today. Please try again tomorrow."),
    "reset_use": (20, timedelta(hours=1), BUSY),
    "scan": (20, timedelta(hours=1), "You've run a lot of scans this hour. Please try again a little later."),
    "demo_fix": (100, timedelta(hours=1), BUSY),
    "connect": (10, timedelta(minutes=15), "Too many attempts to connect. Please try again in a few minutes."),
}
NO_TARGET = "Connect an AWS account before running a scan."
DEMO_CANT_CONNECT = "Demo accounts scan a simulated AWS account. Create an account to connect your own."
TEMPLATE_PATH = "/aws/misconfigly-audit-role.yaml"
SCAN_RUNNING = "A scan is already running. Wait for it to finish, then try again."
SCAN_FAILED = "The scan couldn't finish because AWS didn't respond as expected. Please try again."
SCAN_NOT_FOUND = "Scan not found"
DEMO_ONLY = "Only demo accounts can apply fixes here. In your own account, follow the steps for each finding."
Severity = Literal["critical", "high", "medium", "low"]


def verify_google_token(credential, client_id):
    """The claims of a Google ID token, after checking its signature, audience and expiry."""
    from google.auth.exceptions import GoogleAuthError
    from google.auth.transport import requests
    from google.oauth2 import id_token

    try:
        return id_token.verify_oauth2_token(credential, requests.Request(), client_id)
    except (ValueError, GoogleAuthError) as error:
        raise ValueError("Invalid Google token") from error


def storable(value):
    # Postgres can't hold NUL characters, and lone surrogates can't be encoded at all.
    if any(c == "\x00" or 0xD800 <= ord(c) <= 0xDFFF for c in value):
        raise ValueError("contains characters that can't be stored")
    return value


StorableText = Annotated[str, AfterValidator(storable)]


class Credentials(BaseModel):
    email: EmailStr
    password: StorableText = Field(min_length=1, max_length=200)


class Registration(BaseModel):
    email: EmailStr
    password: StorableText = Field(min_length=8, max_length=200)


class GoogleSignIn(BaseModel):
    credential: str = Field(min_length=1, max_length=8000)


class ForgotPassword(BaseModel):
    email: EmailStr


class ResetPassword(BaseModel):
    token: str = Field(min_length=1, max_length=200)
    new_password: StorableText = Field(min_length=8, max_length=200)


class AwsRole(BaseModel):
    role_arn: str = Field(min_length=20, max_length=2048)


class DemoFixes(BaseModel):
    check_ids: list[str] = Field(min_length=1, max_length=50)


class PasswordChange(BaseModel):
    current_password: StorableText | None = Field(default=None, max_length=200)
    new_password: StorableText = Field(min_length=8, max_length=200)


def public_user(user):
    return {
        "id": str(user["id"]),
        "email": user["email"],
        "is_demo": user["is_demo"],
        "has_password": user["has_password"],
    }


def default_scan_target(store, aws):
    """Demo visitors scan their simulated account. Everyone else scans the AWS account they connected, if any."""

    def scan_target(user, oidc_token=None):
        if user["is_demo"]:
            from . import demo  # Loads moto, so only when a demo scan needs it.

            return demo.target(user, store.demo_fixes(user["id"]))
        connection = store.get_connection(user["id"], new_external_id)
        if not connection["role_arn"] or not aws.configured:
            return None

        def connect():
            return aws.customer_session(oidc_token, connection["role_arn"], connection["external_id"], user["id"])

        return ScanTarget("aws", connect)  # Every region the account has turned on.

    return scan_target


def oidc_token_of(request):
    """Vercel puts a short-lived OIDC token on each request. It isn't there locally."""
    return request.headers.get("x-vercel-oidc-token")


def connection_view(connection, aws):
    return {
        "available": aws.configured,
        "connected": bool(connection["role_arn"]),
        "external_id": connection["external_id"],
        "role_arn": connection["role_arn"],
        "account_id": connection["account_id"],
        "connected_at": connection["connected_at"],
        "scanner_role_arn": aws.scanner_role_arn or None,
        "template_path": TEMPLATE_PATH,
    }


def create_app(
    settings=None, *, store=None, send_email=None, verify_google=verify_google_token, scan_target=None, aws=None
):
    settings = settings or load_settings()
    if send_email is None and settings["smtp"]:
        send_email = smtp_sender(**settings["smtp"])
    store = store or Store(settings["database_url"])
    aws = aws or AwsAccess(settings.get("aws_role_arn", ""), on_vercel=settings["behind_proxy"])
    scan_target = scan_target or default_scan_target(store, aws)
    jwt_secret = settings["jwt_secret"]

    app = FastAPI(title="Misconfigly", docs_url="/api/docs", openapi_url="/api/openapi.json")
    # Sessions use a bearer token rather than cookies, so credentials stay off.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings["cors_origins"],
        allow_methods=["GET", "POST", "PATCH", "DELETE"],
        allow_headers=["Authorization", "Content-Type"],
        expose_headers=["Retry-After"],
    )

    @app.exception_handler(RequestValidationError)
    def invalid_request(request, error):
        # FastAPI's default repeats the input back, which can be a password.
        detail = [{"type": e["type"], "loc": e["loc"], "msg": e["msg"]} for e in error.errors()]
        return JSONResponse(status_code=422, content={"detail": detail})

    def client_ip(request):
        if settings["behind_proxy"] and request.headers.get("x-real-ip"):
            return request.headers["x-real-ip"]
        return request.client.host if request.client else "unknown"

    def enforce_limit(name, subject):
        limit, window, message = RATE_LIMITS[name]
        wait = store.hit_rate_limit(f"{name}:{subject}", limit, window)
        if wait is not None:
            raise HTTPException(status_code=429, detail=message, headers={"Retry-After": str(wait)})

    def session_for(user):
        now = datetime.now(timezone.utc)
        claims = {"sub": str(user["id"]), "ver": user["session_version"], "iat": now, "exp": now + TOKEN_LIFETIME}
        token = jwt.encode(claims, jwt_secret, algorithm="HS256")
        return {"token": token, "user": public_user(user)}

    def current_user(authorization: str = Header(default="")):
        scheme, _, token = authorization.partition(" ")
        if scheme.lower() != "bearer" or not token:
            raise HTTPException(status_code=401, detail=NOT_SIGNED_IN)
        try:
            claims = jwt.decode(token, jwt_secret, algorithms=["HS256"])
            user = store.get_user(uuid.UUID(claims["sub"]))
        except (jwt.InvalidTokenError, KeyError, ValueError):
            raise HTTPException(status_code=401, detail=NOT_SIGNED_IN)
        # A password change or reset raises the version, which ends every older session at once.
        if user is None or claims.get("ver") != user["session_version"]:
            raise HTTPException(status_code=401, detail=NOT_SIGNED_IN)
        return user

    @app.get("/api/health")
    def health():
        return {"ok": True}

    @app.get("/api/auth/options")
    def auth_options():
        return {"password_reset": send_email is not None, "google": bool(settings["google_client_id"])}

    @app.post("/api/auth/register", status_code=201)
    def register(body: Registration, request: Request):
        enforce_limit("register", client_ip(request))
        user = store.create_user(body.email, body.password)
        if user is None:
            raise HTTPException(status_code=409, detail="An account with this email already exists.")
        return session_for(user)

    @app.post("/api/auth/login")
    def login(body: Credentials, request: Request):
        enforce_limit("login", client_ip(request))
        user = store.authenticate(body.email, body.password)
        if user is None:
            raise HTTPException(status_code=401, detail="Email or password is wrong.")
        return session_for(user)

    @app.post("/api/auth/google")
    def google_sign_in(body: GoogleSignIn, request: Request):
        if not settings["google_client_id"]:
            raise HTTPException(status_code=404, detail="Not found")
        enforce_limit("login", client_ip(request))
        try:
            claims = verify_google(body.credential, settings["google_client_id"])
        except ValueError:
            raise HTTPException(status_code=401, detail="Google sign-in could not be verified. Please try again.")
        email = str(claims.get("email") or "")
        if not email or claims.get("email_verified") is not True:
            raise HTTPException(status_code=401, detail="Google did not confirm this email address.")
        user = store.find_or_create_verified_user(email)
        if user is None:
            raise HTTPException(status_code=403, detail="This account can't be signed into with Google.")
        return session_for(user)

    @app.post("/api/auth/demo", status_code=201)
    def demo(request: Request):
        enforce_limit("demo", client_ip(request))
        enforce_limit("demo_all", "all")
        return session_for(store.create_demo_user())

    @app.get("/api/me")
    def me(user=Depends(current_user)):
        return public_user(user)

    @app.post("/api/me/password")
    def change_password(body: PasswordChange, user=Depends(current_user)):
        if user["is_demo"]:
            raise HTTPException(status_code=403, detail="Demo accounts can't have a password. Create your own account to keep your scans.")
        enforce_limit("password_change", user["id"])
        if user["has_password"] and store.authenticate(user["email"], body.current_password or "") is None:
            raise HTTPException(status_code=400, detail="Your current password is not correct.")
        store.set_password(user["id"], body.new_password)
        # Every older session just ended, so this one needs a new token to carry on.
        return session_for(store.get_user(user["id"]))

    @app.post("/api/password/forgot")
    def forgot_password(body: ForgotPassword, request: Request):
        if send_email is None:
            raise HTTPException(status_code=503, detail="Password reset isn't available right now.")
        enforce_limit("reset_ip", client_ip(request))
        enforce_limit("reset_all", "all")
        email = body.email.lower()
        limit, window, _ = RATE_LIMITS["reset_email"]
        token = None if store.hit_rate_limit(f"reset_email:{email}", limit, window) else store.create_reset_token(email)
        if token:
            try:
                send_email(
                    email,
                    "Reset your Misconfigly password",
                    "Reset your password",
                    f"Someone asked to reset the password for the Misconfigly account {email}. "
                    "Use the button below to choose a new one. The link expires in 15 minutes.",
                    "Choose a new password",
                    f"{settings['app_url']}/reset-password?token={token}",
                    "If this wasn't you, you can ignore this email and your password won't change.",
                )
            except Exception:
                logger.exception("Could not send a password reset email")
        return {"detail": RESET_SENT}

    @app.post("/api/password/reset")
    def reset_password(body: ResetPassword, request: Request):
        enforce_limit("reset_use", client_ip(request))
        if not store.reset_password(body.token, body.new_password):
            raise HTTPException(status_code=400, detail=RESET_INVALID)
        return {"ok": True}

    # Scans

    @app.get("/api/checks")
    def checks():
        return {"checks": catalog()}

    @app.post("/api/scans", status_code=201)
    def start_scan(request: Request, user=Depends(current_user)):
        target = scan_target(user, oidc_token_of(request))
        if target is None:
            raise HTTPException(status_code=409, detail=NO_TARGET)
        enforce_limit("scan", user["id"])
        scan = store.start_scan(user["id"], target.source)
        if scan is None:
            raise HTTPException(status_code=409, detail=SCAN_RUNNING)
        try:
            result = run_scan(target.connect(), target.regions)
        except ConnectionFailed as error:
            store.fail_scan(scan["id"], error.message)
            raise HTTPException(status_code=502, detail=error.message)
        except Exception:
            logger.exception("Scan %s failed", scan["id"])
            store.fail_scan(scan["id"], SCAN_FAILED)
            raise HTTPException(status_code=502, detail=SCAN_FAILED)
        finally:
            if target.disconnect:
                target.disconnect()
        severities = {check_id: c.severity for check_id, c in CHECKS.items()}
        scan = store.finish_scan(scan["id"], result, summarize(result.findings), severities)
        return scan_view(scan)

    def own_account_user(user=Depends(current_user)):
        if user["is_demo"]:
            raise HTTPException(status_code=403, detail=DEMO_CANT_CONNECT)
        return user

    @app.get("/api/connection")
    def get_connection(user=Depends(own_account_user)):
        return connection_view(store.get_connection(user["id"], new_external_id), aws)

    @app.post("/api/connection")
    def connect_account(body: AwsRole, request: Request, user=Depends(own_account_user)):
        enforce_limit("connect", user["id"])
        connection = store.get_connection(user["id"], new_external_id)
        try:
            account_id = parse_role_arn(body.role_arn)
            # Proves the role works before saving it: the stack exists, trusts Misconfigly and has this ExternalId.
            aws.customer_session(oidc_token_of(request), body.role_arn, connection["external_id"], user["id"])
        except ConnectionFailed as error:
            raise HTTPException(status_code=400, detail=error.message)
        return connection_view(store.save_connection(user["id"], body.role_arn.strip(), account_id), aws)

    @app.delete("/api/connection")
    def disconnect_account(user=Depends(own_account_user)):
        store.get_connection(user["id"], new_external_id)
        return connection_view(store.remove_connection(user["id"], new_external_id), aws)

    def demo_user(user=Depends(current_user)):
        if not user["is_demo"]:
            raise HTTPException(status_code=403, detail=DEMO_ONLY)
        return user

    @app.get("/api/demo/fixes")
    def demo_fixes(user=Depends(demo_user)):
        return {"fixed": sorted(store.demo_fixes(user["id"]))}

    @app.post("/api/demo/fixes")
    def apply_demo_fixes(body: DemoFixes, user=Depends(demo_user)):
        unknown = [c for c in body.check_ids if c not in CHECKS]
        if unknown:
            raise HTTPException(status_code=400, detail="There is no check called " + ", ".join(unknown[:3]))
        enforce_limit("demo_fix", user["id"])
        from .demo import with_dependencies

        return {"fixed": sorted(store.add_demo_fixes(user["id"], with_dependencies(body.check_ids)))}

    @app.delete("/api/demo/fixes")
    def reset_demo_fixes(user=Depends(demo_user)):
        store.clear_demo_fixes(user["id"])
        return {"fixed": []}

    @app.get("/api/scans")
    def list_scans(user=Depends(current_user)):
        return {"scans": [scan_view(s) for s in store.list_scans(user["id"])]}

    @app.get("/api/scans/{scan_id}")
    def get_scan(
        scan_id: str,
        severity: Annotated[list[Severity] | None, Query()] = None,
        service: Annotated[str | None, Query(max_length=40)] = None,
        status: Literal["fail", "pass", "error"] | None = None,
        user=Depends(current_user),
    ):
        try:
            scan_uuid = uuid.UUID(scan_id)
        except ValueError:
            raise HTTPException(status_code=404, detail=SCAN_NOT_FOUND)
        scan, rows = store.get_scan(user["id"], scan_uuid)
        if scan is None:
            raise HTTPException(status_code=404, detail=SCAN_NOT_FOUND)
        return {
            "scan": scan_view(scan),
            "services": sorted({CHECKS[r["check_id"]].service for r in rows if r["check_id"] in CHECKS}),
            "checks": grouped_checks(rows, scan["account_id"], set(severity or []), service, status),
        }

    return app
