import os
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent


def _list(name):
    return [item.strip() for item in os.environ.get(name, "").split(",") if item.strip()]


def load_settings():
    load_dotenv(BASE_DIR / ".env")
    missing = [name for name in ("DATABASE_URL", "JWT_SECRET") if not os.environ.get(name)]
    if missing:
        raise RuntimeError(f"Missing required settings: {', '.join(missing)}")
    cors_origins = _list("CORS_ALLOWED_ORIGINS")
    # Links in emails point at the frontend, the first allowed origin.
    app_url = (cors_origins[0] if cors_origins else "http://localhost:5190").rstrip("/")
    smtp_user = os.environ.get("SMTP_USER", "")
    smtp_password = os.environ.get("SMTP_PASSWORD", "")
    return {
        "database_url": os.environ["DATABASE_URL"],
        "jwt_secret": os.environ["JWT_SECRET"],
        "cors_origins": cors_origins,
        "app_url": app_url,
        # Without it, Continue with Google is turned off.
        "google_client_id": os.environ.get("GOOGLE_CLIENT_ID", ""),
        # Without these, password reset is hidden.
        "smtp": (smtp_user and smtp_password and {
            "host": os.environ.get("SMTP_HOST", "smtp.gmail.com"),
            "port": int(os.environ.get("SMTP_PORT", "587")),
            "user": smtp_user,
            "password": smtp_password,
            "sender": os.environ.get("EMAIL_FROM") or smtp_user,
        }) or None,
        # Vercel sets the client address itself. Elsewhere the header could be forged.
        "behind_proxy": bool(os.environ.get("VERCEL")),
        # The MisconfiglyScanner role from infra/misconfigly-service.yaml. Without it, AWS accounts can't be connected.
        "aws_role_arn": os.environ.get("AWS_ROLE_ARN", ""),
    }
