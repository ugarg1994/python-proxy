# FastAPI Proxy Forwarder

Small FastAPI service that forwards incoming requests to an upstream API.

It supports two modes:

- Plain proxy: forwards method, path, query string, headers, and body.
- CTIX signing proxy: automatically appends `AccessID`, `Signature`, and `Expires` query params using the HMAC-SHA1 flow shown in `Intel Exchange Postman API.json`.

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
- `POST /ctix/request`: send a CTIX request as JSON while the proxy adds CTIX authentication.
- `ANY /{path}`: forwards to `{UPSTREAM_BASE_URL}/{path}`.

## CTIX Request Format

Use `POST /ctix/request` when you want your client to explicitly reference a CTIX API path from `Intel Exchange Postman API.json` and let the proxy inject authentication.

Example request for the CTIX `Ping` endpoint:

```bash
curl -X POST https://your-render-service.onrender.com/ctix/request \
  -H "Content-Type: application/json" \
  -d '{
    "method": "GET",
    "path": "ping/"
  }'
```

Example request for a CTIX endpoint with query params:

```bash
curl -X POST https://your-render-service.onrender.com/ctix/request \
  -H "Content-Type: application/json" \
  -d '{
    "method": "GET",
    "path": "ingestion/file/3cd05d6d-3ed4-49ae-8866-4d8f87542fa1/",
    "params": {
      "type": "basic"
    }
  }'
```

Request body fields:

- `method`: HTTP verb to send to CTIX.
- `path`: CTIX path from the Postman collection, relative to `UPSTREAM_BASE_URL`.
- `params`: optional query parameters.
- `headers`: optional extra headers.
- `json`: optional JSON body.
- `body`: optional raw string body.

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
- If CTIX credentials are not set, the proxy forwards requests without signing.
