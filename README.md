# Misconfigly

Misconfigly audits an AWS account for the security misconfigurations attackers look for first: public S3 buckets, a root account without MFA, SSH open to the internet, disabled CloudTrail, old access keys and more. Each finding explains why it matters and how to fix it.

> **Status:** in progress. The foundation is done: accounts, Google sign-in, password reset, rate limits and private demo accounts. The scanner and the rest are being added in stages.

## Planned features

- About 30 checks based on the CIS AWS Foundations Benchmark, run with boto3
- Fixes for each finding as console steps, an AWS CLI command and Terraform
- A security score with history and a trend over time
- A connection through a read-only IAM role created by a CloudFormation template (STS AssumeRole with an ExternalId), so no access keys are stored
- A demo that scans a simulated AWS account, so visitors need no AWS account
- PDF and CSV reports
- Scheduled scans, emails about new critical findings and a plain-English summary

## Stack

- **Backend:** FastAPI, PostgreSQL (psycopg 3), PyJWT, boto3
- **Frontend:** React 18, Vite, React Router
- **Hosting:** Vercel

## Run it locally

Backend (Python 3.12 and a Postgres database):

```bash
cd Backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
cp .env.example .env   # then set DATABASE_URL and JWT_SECRET
uvicorn asgi:app --port 8030
```

Frontend (Node 22):

```bash
cd Frontend
npm install
npm run dev            # http://localhost:5190, proxies /api to port 8030
```

## Tests

```bash
cd Backend
python -m pytest
```

The tests start their own temporary Postgres with pgserver, so they need no database setup. CI runs them and builds the frontend on every push.
