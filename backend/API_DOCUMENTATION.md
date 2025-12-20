# TOR Unveil - Unified Backend API Documentation

## Overview

The unified backend integrates all features into a single, comprehensive API service:

- **Tor ControlPort Monitoring** - Real-time circuit tracking via Stem
- **Packet Capture** - Live network traffic sniffing with Scapy
- **PCAP Analysis** - Forensic analysis of captured traffic using dpkt
- **ML Correlation** - Heuristic and ML-based circuit correlation
- **TOR Node Scraping** - Fetch relay information from Onionoo
- **Report Generation** - Generate forensic HTML/PDF reports

## Base URL

```
http://localhost:5000/api
```

## Authentication

All API endpoints (except `/api/health`) require an API key sent in the request header:

```
X-API-Key: changeme
```

Default API key is `changeme` (configurable via `API_KEY` environment variable).

---

## Endpoints

### Health & Status

#### `GET /api/health`

Health check endpoint (no authentication required).

**Response:**
```json
{
  "status": "healthy",
  "timestamp": "2024-01-15T10:30:00",
  "version": "2.0.0-unified",
  "features": {
    "stem": true,
    "scapy": true,
    "dpkt": true,
    "sklearn": true,
    "reportlab": true
  },
  "tor_connected": true
}
```

#### `GET /api/status`

Get comprehensive system status.

**Response:**
```json
{
  "status": "operational",
  "uptime_seconds": 3600,
  "tor_connected": true,
  "circuits_count": 15,
  "packets_captured": 5000,
  "sniffer_active": true,
  "total_requests": 123,
  "features_enabled": {...}
}
```

---

### Tor Circuit Management

#### `GET /api/circuits`

Get all active Tor circuits.

**Response:**
```json
{
  "circuits": [
    {
      "id": 1,
      "status": "BUILT",
      "purpose": "GENERAL",
      "path": [
        {"fingerprint": "ABC123...", "nickname": "GuardNode1"},
        {"fingerprint": "DEF456...", "nickname": "MiddleNode1"},
        {"fingerprint": "GHI789...", "nickname": "ExitNode1"}
      ],
      "build_flags": ["NEED_CAPACITY"],
      "created_at": 1640000000.0
    }
  ],
  "count": 1,
  "timestamp": "2024-01-15T10:30:00"
}
```

#### `POST /api/circuits/<circuit_id>/close`

Close a specific circuit.

**Response:**
```json
{
  "success": true,
  "circuit_id": 1
}
```

---

### Relay Information

#### `GET /api/relays`

Get all TOR relays from Onionoo.

**Response:**
```json
{
  "relays": [
    {
      "n": "relay_nickname",
      "f": "fingerprint",
      "a": ["1.2.3.4"],
      "c": "US",
      "bw": 1000000
    }
  ]
}
```

#### `GET /api/relays/<fingerprint>`

Get detailed information about a specific relay.

**Response:**
```json
{
  "nickname": "relay_name",
  "fingerprint": "ABC123...",
  "or_addresses": ["1.2.3.4:9001"],
  "exit_policy": [...],
  "bandwidth": 1000000,
  "country": "US",
  "flags": ["Exit", "Fast", "Valid"]
}
```

#### `GET /api/tor/statistics`

Get TOR network statistics.

**Response:**
```json
{
  "total_relays": 6000,
  "exit_nodes": 1200,
  "guard_nodes": 2000,
  "total_bandwidth": 1000000000
}
```

---

### Packet Capture

#### `POST /api/sniffer/start`

Start real-time packet capture.

**Request Body:**
```json
{
  "interface": null,
  "packet_limit": 5000
}
```

**Response:**
```json
{
  "status": "started",
  "interface": "default",
  "packet_limit": 5000
}
```

#### `POST /api/sniffer/stop`

Stop packet capture.

**Response:**
```json
{
  "status": "stopped",
  "packets_captured": 5000
}
```

#### `GET /api/sniffer/packets`

Get captured packets with pagination.

**Query Parameters:**
- `limit` (default: 100) - Number of packets to return
- `offset` (default: 0) - Starting position

**Response:**
```json
{
  "packets": [
    {
      "timestamp": 1640000000.0,
      "timestamp_iso": "2024-01-15T10:30:00",
      "src_ip": "192.168.1.100",
      "dst_ip": "1.2.3.4",
      "src_port": 54321,
      "dst_port": 443,
      "protocol": "TCP",
      "length": 1500,
      "tor_related": true
    }
  ],
  "total": 5000,
  "limit": 100,
  "offset": 0
}
```

#### `GET /api/sniffer/statistics`

Get packet capture statistics.

**Response:**
```json
{
  "total_packets": 5000,
  "tor_packets": 150,
  "tor_percentage": 3.0,
  "is_running": true
}
```

#### `GET /api/sniffer/stream`

Stream live packets as Server-Sent Events (SSE).

Connect using EventSource:
```javascript
const eventSource = new EventSource('http://localhost:5000/api/sniffer/stream');
eventSource.onmessage = (event) => {
  const packet = JSON.parse(event.data);
  console.log(packet);
};
```

---

### PCAP Analysis

#### `POST /api/pcap/upload`

Upload and analyze a PCAP file.

**Request:**
- Content-Type: `multipart/form-data`
- File field: `file`
- Supported formats: `.pcap`, `.pcapng`

**Response:**
```json
{
  "status": "success",
  "filename": "capture.pcap",
  "analysis": {
    "total_packets": 10000,
    "flows": {
      "192.168.1.100:54321-1.2.3.4:443": 150
    },
    "packets": [...],
    "analysis_time": "2024-01-15T10:30:00"
  }
}
```

#### `POST /api/pcap/analyze`

Analyze currently captured packets.

**Response:**
```json
{
  "total_packets": 5000,
  "tor_packets": 150,
  "tor_percentage": 3.0,
  "timestamp": "2024-01-15T10:30:00"
}
```

---

### Correlation

#### `POST /api/correlate`

Correlate captured packets with Tor circuits.

**Response:**
```json
{
  "correlations": [
    {
      "packet": {...},
      "circuit_id": 1,
      "confidence": 0.6,
      "method": "time_proximity"
    }
  ],
  "total_matches": 25,
  "timestamp": "2024-01-15T10:30:00"
}
```

#### `GET /api/correlate/results`

Get previous correlation results.

**Response:**
```json
{
  "correlations": [...],
  "total_matches": 25,
  "timestamp": "2024-01-15T10:30:00"
}
```

---

### Report Generation

#### `POST /api/reports/generate`

Generate a forensic HTML report.

**Response:**
```json
{
  "report_id": "report_1640000000",
  "path": "/path/to/report.html",
  "url": "/api/reports/report_1640000000.html"
}
```

#### `GET /api/reports/<filename>`

Download a generated report.

**Response:**
HTML file download

---

## Usage Examples

### Python

```python
import requests

API_URL = "http://localhost:5000/api"
API_KEY = "changeme"
headers = {"X-API-Key": API_KEY}

# Check health
response = requests.get(f"{API_URL}/health")
print(response.json())

# Get circuits
response = requests.get(f"{API_URL}/circuits", headers=headers)
circuits = response.json()["circuits"]
print(f"Active circuits: {len(circuits)}")

# Start packet capture
response = requests.post(
    f"{API_URL}/sniffer/start",
    headers=headers,
    json={"packet_limit": 1000}
)
print(response.json())

# Upload PCAP
with open("capture.pcap", "rb") as f:
    files = {"file": f}
    response = requests.post(
        f"{API_URL}/pcap/upload",
        headers=headers,
        files=files
    )
print(response.json())
```

### JavaScript

```javascript
const API_URL = "http://localhost:5000/api";
const API_KEY = "changeme";

// Get circuits
fetch(`${API_URL}/circuits`, {
  headers: { "X-API-Key": API_KEY }
})
  .then(res => res.json())
  .then(data => console.log(data.circuits));

// Stream live packets
const eventSource = new EventSource(`${API_URL}/sniffer/stream`);
eventSource.onmessage = (event) => {
  const packet = JSON.parse(event.data);
  console.log("New packet:", packet);
};
```

### cURL

```bash
# Health check
curl http://localhost:5000/api/health

# Get circuits
curl -H "X-API-Key: changeme" \
  http://localhost:5000/api/circuits

# Start sniffer
curl -X POST \
  -H "X-API-Key: changeme" \
  -H "Content-Type: application/json" \
  -d '{"packet_limit": 1000}' \
  http://localhost:5000/api/sniffer/start

# Upload PCAP
curl -X POST \
  -H "X-API-Key: changeme" \
  -F "file=@capture.pcap" \
  http://localhost:5000/api/pcap/upload
```

---

## Error Handling

All errors follow standard HTTP status codes:

- `400` - Bad Request (invalid parameters)
- `401` - Unauthorized (invalid API key)
- `404` - Not Found
- `500` - Internal Server Error

Error response format:
```json
{
  "error": "Description of the error"
}
```

---

## Environment Variables

Configure the backend using environment variables:

- `API_KEY` - API authentication key (default: `changeme`)
- `TOR_CONTROL_HOST` - Tor ControlPort host (default: `127.0.0.1`)
- `TOR_CONTROL_PORT` - Tor ControlPort port (default: `9051`)
- `BACKEND_PORT` - Backend server port (default: `5000`)

Example:
```bash
export API_KEY="my_secret_key"
export TOR_CONTROL_PORT=9051
python backend.py
```

---

## Feature Detection

The backend gracefully handles missing dependencies. Check feature availability:

```python
response = requests.get("http://localhost:5000/api/health")
features = response.json()["features"]

if features["scapy"]:
    # Packet capture available
    pass

if features["stem"]:
    # Tor integration available
    pass
```

---

## Rate Limiting

Currently no rate limiting is implemented. Consider implementing rate limiting for production deployments.

---

## Security Considerations

1. **Change the default API key** in production
2. **Use HTTPS** for production deployments
3. **Restrict API access** to trusted networks
4. **Sanitize file uploads** to prevent malicious files
5. **Run with appropriate permissions** (packet capture may require elevated privileges)

---

## Support & Documentation

- GitHub: [Repository URL]
- Issues: [Issues URL]
- Version: 2.0.0-unified
- Last Updated: 2024-01-15
