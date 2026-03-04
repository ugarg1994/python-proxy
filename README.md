# FastAPI Proxy Forwarder

Small FastAPI service that forwards incoming requests to an upstream API.

It forwards the incoming request to CTIX by:

- keeping the same HTTP method
- keeping the same path, query string, headers, and body
- replacing only the base URL with `UPSTREAM_BASE_URL`
- automatically appending `AccessID`, `Signature`, and `Expires` when CTIX credentials are configured

## Setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

Set `UPSTREAM_BASE_URL` in your environment or `.env` loader of choice.

Example:

```bash
export UPSTREAM_BASE_URL="https://sample.domain.com/ctixapi/"
export CTIX_ACCESS_ID="your-access-id"
export CTIX_SECRET_KEY="your-secret-key"
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

## Endpoints

- `GET /health`: proxy health/config check.
- `ANY /{path}`: forwards to `{UPSTREAM_BASE_URL}/{path}`.

## Usage

Example GET request:

```bash
curl https://your-render-service.onrender.com/ping/
```

This becomes:

```bash
GET {UPSTREAM_BASE_URL}/ping/
```

Example POST request:

```bash
curl -X POST https://your-render-service.onrender.com/ingestion/reports/ \
  -H "Content-Type: application/json" \
  -d '{"name":"example"}'
```

This becomes:

```bash
POST {UPSTREAM_BASE_URL}/ingestion/reports/
Content-Type: application/json

{"name":"example"}
```

Query strings are preserved too. For example:

```bash
curl "https://your-render-service.onrender.com/ingestion/reports/?type=basic"
```

becomes:

```bash
GET {UPSTREAM_BASE_URL}/ingestion/reports/?type=basic
```

## Deploy On Render

Create a new Web Service and use:

- Build command: `pip install -r requirements.txt`
- Start command: `uvicorn app.main:app --host 0.0.0.0 --port $PORT`

Set these environment variables in Render:

- `UPSTREAM_BASE_URL` such as `https://sample.domain.com/ctixapi/`
- `CTIX_ACCESS_ID` if CTIX signing is needed
- `CTIX_SECRET_KEY` if CTIX signing is needed
- `CTIX_SIGNATURE_TTL` optional, defaults to `25`
- `PROXY_TIMEOUT` optional, defaults to `60`

## Notes

- Hop-by-hop headers such as `Connection` and `Transfer-Encoding` are removed.
- Redirects are passed through instead of being followed by the proxy.
- If CTIX credentials are not set, the proxy still forwards requests but does not add CTIX auth parameters.
