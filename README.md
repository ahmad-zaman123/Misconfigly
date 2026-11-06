# Misconfigly

Misconfigly audits an AWS account for the security misconfigurations attackers look for first: public S3 buckets, a root account without MFA, SSH open to the internet, disabled CloudTrail, old access keys and more. Each finding explains why it matters and how to fix it.

> **Status:** in progress. Done so far: accounts, the scanner with 37 CIS checks, fixes, the score, the simulated demo account and connecting a real AWS account. History, reports and alerts are next.

## Planned features

- 37 checks based on the CIS AWS Foundations Benchmark, run with boto3
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

## How the AWS connection works

Misconfigly never asks for access keys.

1. On Vercel, each request to the backend carries a short-lived OIDC token. AWS trusts Vercel as an identity provider, so the backend exchanges that token for its own role, `MisconfiglyScanner` (`infra/misconfigly-service.yaml`). That role can do one thing: assume roles named `MisconfiglyAudit`.
2. A customer creates `MisconfiglyAudit` in their account from `Frontend/public/aws/misconfigly-audit-role.yaml`, with one command in AWS CloudShell. It has AWS's read-only `SecurityAudit` policy and trusts only the scanner role, and only with that customer's ExternalId.
3. Each scan assumes the customer's role for at most an hour. Only the role ARN is stored.

Locally, with `AWS_ROLE_ARN` set, your own AWS CLI profile stands in for the scanner role.

## Deploy

The backend and frontend are two Vercel projects from this repository, with root directories `Backend` and `Frontend`.

1. **Database.** Create a Neon Postgres database. From your own terminal, run `DATABASE_URL=... python migrate.py` in `Backend`. It is safe to run again after each update.
2. **Backend project.** Set `DATABASE_URL`, `JWT_SECRET` (a long random string) and `CORS_ALLOWED_ORIGINS` (the frontend's address). In Settings → Security, turn on Secure backend access with OIDC federation in Team issuer mode.
3. **Scanner role.** In the AWS account that hosts Misconfigly, create a CloudFormation stack from `infra/misconfigly-service.yaml` with your Vercel team slug and the backend project's name. Set the backend's `AWS_ROLE_ARN` to the stack's `ScannerRoleArn` output and redeploy.
4. **Frontend project.** Set `VITE_API_URL` to the backend's address.
