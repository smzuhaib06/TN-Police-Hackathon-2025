TOR Unveil - Stem backend
=========================

This folder contains a small prototype backend that connects to a local Tor control port using Stem and exposes a tiny REST API for the dashboard.

Prerequisites
-------------
- Python 3.8+
- A local Tor instance with ControlPort enabled and either CookieAuthentication or a control password set.

Enable ControlPort (example torrc additions)
-------------------------------------------
# allow control connections on localhost
ControlPort 9051
# enable cookie authentication (recommended)
CookieAuthentication 1
# OR, use a hashed control password (not shown here)
# HashedControlPassword <hash>

If you configure CookieAuthentication, the backend will try to authenticate with the cookie. If you use a password, set env var:

  TOR_CONTROL_PASSWORD=<your-password>

Install
-------
From the project root (where this README lives):

  pip install -r backend/requirements.txt

Run the backend
---------------
Run the service (defaults to port 5000):

  python backend/stem_service.py

Endpoints
---------
- GET /api/health — basic health check
- GET /api/circuits — returns a snapshot of circuits observed via the ControlPort
- GET /api/relays — fetches Onionoo summary (public API)
- GET /api/trace?exit=<fingerprint> — naive correlation of exit -> entry hops
- POST /api/pcap — upload pcap file (multipart form field `file`) to extract flows
- POST /api/report/generate — generate an HTML report from provided JSON payload (returns filesystem path)

Docker Usage
------------
To run the backend and frontend in containers:

1. Build and start services:

```sh
docker-compose up --build
```

2. The backend will be available at http://localhost:5000 (API key required).
   The static frontend will be available at http://localhost:8000.

3. API key authentication:
   - All endpoints except /api/health require header `X-API-KEY: changeme` (or your chosen key).
   - Set API_KEY in docker-compose.yml or as an environment variable.

4. To connect to your local Tor instance, ensure ControlPort is enabled and accessible from the container. For Windows, use `host.docker.internal` as TOR_CONTROL_HOST.

Example API call:

```sh
curl -H "X-API-KEY: changeme" http://localhost:5000/api/circuits
```

Notes & Next Steps
------------------
- This is a prototype and intentionally small. It demonstrates how to gather circuits via Stem and provide simple correlation logic.
- For production or larger datasets, consider adding:
  - persistent database (Postgres/TimescaleDB)
  - background jobs for CollecTor ingestion
  - stronger correlation heuristics and probabilistic models
  - secure deployment and authentication

If you want, I can:
 - add a Dockerfile and docker-compose for local testing
 - wire the frontend (`main.js`) to call `/api/relays` and `/api/circuits`
 - add a simple Postman collection or curl examples
