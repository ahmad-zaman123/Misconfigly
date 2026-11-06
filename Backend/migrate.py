"""Creates or updates the database tables. Safe to run more than once.

    DATABASE_URL=postgresql://... python migrate.py

It reads DATABASE_URL from the environment, or from Backend/.env.
"""

import os
import sys

from dotenv import load_dotenv

from app.config import BASE_DIR
from app.store import Store


def main():
    load_dotenv(BASE_DIR / ".env")
    url = os.environ.get("DATABASE_URL")
    if not url:
        sys.exit("Set DATABASE_URL first.")
    Store(url).init_schema()
    print("The database is up to date.")


if __name__ == "__main__":
    main()
