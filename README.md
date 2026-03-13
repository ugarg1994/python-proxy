# FastAPI Proxy Forwarder

Small FastAPI service that forwards incoming requests to an upstream API.

It forwards the incoming request to CTIX by:

- keeping the same HTTP method
- keeping the same path, query string, headers, and body
- replacing only the base URL with `UPSTREAM_BASE_URL`
- automatically appending `AccessID`, `Signature`, and `Expires` when CTIX credentials are configured

It also exposes Security Copilot metadata endpoints so you can register the proxy directly from your Render deployment.

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
- `GET /security-copilot/openapi.json`: Security Copilot-compatible OpenAPI spec.
- `GET /security-copilot/plugin.yaml`: Security Copilot plugin manifest.
- `GET /security-copilot/threat-data/search/`: Security Copilot-friendly CTIX CQL search wrapper.
- `GET /security-copilot/search-indicators-by-value/`: natural-language-friendly indicator lookup.
- `GET /security-copilot/search-reports-by-keyword/`: natural-language-friendly report search.
- `GET /security-copilot/search-threat-data-by-type/`: simple threat data type search.
- `GET /security-copilot/search-threat-data-by-tag/`: simple threat data tag search.
- `GET /security-copilot/search-threat-data-advanced/`: multi-filter threat data search.
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
- `PUBLIC_BASE_URL` such as `https://python-proxy-tume.onrender.com`
- `CTIX_ACCESS_ID` if CTIX signing is needed
- `CTIX_SECRET_KEY` if CTIX signing is needed
- `CTIX_SIGNATURE_TTL` optional, defaults to `25`
- `PROXY_TIMEOUT` optional, defaults to `60`

## Security Copilot

After deployment, use these Render-hosted URLs:

- Plugin manifest: `https://python-proxy-tume.onrender.com/security-copilot/plugin.yaml`
- OpenAPI spec: `https://python-proxy-tume.onrender.com/security-copilot/openapi.json`

The generated OpenAPI spec is adapted from `Intel Exchange Swagger API.json` to make it easier to use with Security Copilot:

- `openapi` is rewritten to `3.0.1`
- `servers` points to your Render URL
- CTIX auth query parameters are removed from operations because the proxy injects them
- the CTIX ping operation is exposed as `/ping/` on the proxy
- only a small read-only CTIX subset is exposed for Security Copilot:
  - `/ping/`
  - `/feed-sources/collection/`
  - `/security-copilot/threat-data/search/`
  - `/security-copilot/search-indicators-by-value/`
  - `/security-copilot/search-reports-by-keyword/`
  - `/security-copilot/search-threat-data-by-type/`
  - `/security-copilot/search-threat-data-by-tag/`
  - `/security-copilot/search-threat-data-advanced/`
  - `/reports/`
  - `/reports/{report_id}/`
  - `/reports/{report_id}/run/`
  - `/subscriber/polling-report/`
  - `/subscriber/inboxing-report/`

The CQL search wrapper lets Security Copilot perform threat data searches without calling the original CTIX POST body directly.

Example:

```bash
curl "https://python-proxy-tume.onrender.com/security-copilot/threat-data/search/?query=type%20%3D%20%22indicator%22"
```

Prompt pattern for Security Copilot:

```text
Use CTIX Proxy to search CTIX threat data by CQL query. Set query to: type = "indicator"
```

Simpler prompts that are closer to MCP-style usage:

```text
Use CTIX Proxy to search indicators for 1.1.1.1
```

```text
Use CTIX Proxy to search reports for phishing
```

```text
Use CTIX Proxy to search threat data for malware
```

```text
Use CTIX Proxy to search threat data tagged phishing
```

For multi-filter searches, use prompts like:

```text
Use CTIX Proxy to search threat data with value 1.1.1.1, tag phishing, and object types malware and threat-actor.
```

```text
Use CTIX Proxy to search threat data with object types indicator, malware, threat-actor and sources dac01547-0550-4a5f-a51c-209142c7bb31,92614d49-0766-4331-bbc0-be4e78ad7b3a.
```

The advanced endpoint also supports name resolution:

- `source_names`: resolves source names by calling CTIX `/feed-sources/` and substituting matched source IDs.
- `tag_names`: resolves tag names by calling CTIX `/tags/` and searching with the matched canonical tag names.

Example prompt:

```text
Use CTIX Proxy to search threat data with source names Threatfeed and Threatfeed1, tag names phishing and malware, and object types malware and threat-actor.
```

```text
Use CTIX Proxy to search threat data with object type indicator, related object threat-actor, and related object value APT28.
```

## Notes

- Hop-by-hop headers such as `Connection` and `Transfer-Encoding` are removed.
- Redirects are passed through instead of being followed by the proxy.
- If CTIX credentials are not set, the proxy still forwards requests but does not add CTIX auth parameters.
