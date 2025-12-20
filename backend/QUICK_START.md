# TOR Unveil Backend - Quick Start Guide

## Installation

### 1. Install Python Dependencies

```bash
cd backend
pip install -r requirements.txt
```

### 2. Verify Installation

```bash
python -c "import flask, stem, scapy, dpkt, sklearn; print('All dependencies installed!')"
```

## Running the Backend

### Option 1: Direct Execution

```bash
cd backend
python backend.py
```

### Option 2: With Environment Variables

```bash
export API_KEY="your_secret_key"
export TOR_CONTROL_PORT=9051
python backend.py
```

### Option 3: Windows PowerShell

```powershell
cd backend
$env:API_KEY="your_secret_key"
python backend.py
```

## Quick Testing

### 1. Check Health (No Auth Required)

```bash
curl http://localhost:5000/api/health
```

Expected output:
```json
{
  "status": "healthy",
  "version": "2.0.0-unified",
  "features": {...}
}
```

### 2. Get System Status

```bash
curl -H "X-API-Key: changeme" http://localhost:5000/api/status
```

### 3. Get Tor Circuits

```bash
curl -H "X-API-Key: changeme" http://localhost:5000/api/circuits
```

### 4. Start Packet Capture

```bash
curl -X POST \
  -H "X-API-Key: changeme" \
  -H "Content-Type: application/json" \
  -d '{"packet_limit": 1000}' \
  http://localhost:5000/api/sniffer/start
```

**Note:** Packet capture requires administrator/root privileges on most systems.

### 5. Get TOR Network Statistics

```bash
curl -H "X-API-Key: changeme" http://localhost:5000/api/tor/statistics
```

## Common Issues & Solutions

### Issue: "Scapy not available" or Permission Errors

**Solution:** Run with elevated privileges:

**Linux/Mac:**
```bash
sudo python backend.py
```

**Windows (PowerShell as Administrator):**
```powershell
python backend.py
```

### Issue: "Failed to connect to Tor"

**Possible causes:**
1. Tor Browser not running
2. Wrong ControlPort configuration
3. Authentication issues

**Solutions:**

1. Start Tor Browser first
2. Check Tor ControlPort settings in `torrc`:
   ```
   ControlPort 9051
   CookieAuthentication 1
   ```
3. Verify port in environment:
   ```bash
   export TOR_CONTROL_PORT=9051
   ```

### Issue: "Module not found" errors

**Solution:** Install missing dependencies:
```bash
pip install -r requirements.txt
```

Or install individually:
```bash
pip install flask flask-cors stem scapy dpkt scikit-learn numpy requests jinja2 reportlab
```

### Issue: "Port already in use"

**Solution:** Change the backend port:
```bash
export BACKEND_PORT=5001
python backend.py
```

## Feature-Specific Usage

### Packet Capture Workflow

```bash
# 1. Start capture
curl -X POST -H "X-API-Key: changeme" \
  -H "Content-Type: application/json" \
  -d '{"packet_limit": 5000}' \
  http://localhost:5000/api/sniffer/start

# 2. Wait for packets to be captured (check status)
curl -H "X-API-Key: changeme" \
  http://localhost:5000/api/sniffer/statistics

# 3. Stop capture
curl -X POST -H "X-API-Key: changeme" \
  http://localhost:5000/api/sniffer/stop

# 4. Get captured packets
curl -H "X-API-Key: changeme" \
  "http://localhost:5000/api/sniffer/packets?limit=100"

# 5. Analyze packets
curl -X POST -H "X-API-Key: changeme" \
  http://localhost:5000/api/pcap/analyze
```

### PCAP Upload & Analysis

```bash
# Upload a PCAP file
curl -X POST -H "X-API-Key: changeme" \
  -F "file=@/path/to/capture.pcap" \
  http://localhost:5000/api/pcap/upload
```

### Circuit Correlation

```bash
# 1. Ensure you have circuits
curl -H "X-API-Key: changeme" \
  http://localhost:5000/api/circuits

# 2. Ensure you have packets
curl -H "X-API-Key: changeme" \
  "http://localhost:5000/api/sniffer/packets?limit=10"

# 3. Run correlation
curl -X POST -H "X-API-Key: changeme" \
  http://localhost:5000/api/correlate

# 4. Get results
curl -H "X-API-Key: changeme" \
  http://localhost:5000/api/correlate/results
```

### Report Generation

```bash
# Generate forensic report
curl -X POST -H "X-API-Key: changeme" \
  http://localhost:5000/api/reports/generate

# Download report (use report_id from previous response)
curl -H "X-API-Key: changeme" \
  http://localhost:5000/api/reports/report_1640000000.html \
  -o report.html
```

## Integration with Frontend

The backend is designed to work with the TOR Unveil frontend. To run the full stack:

1. Start the backend:
   ```bash
   cd backend
   python backend.py
   ```

2. In another terminal, serve the frontend:
   ```bash
   # From project root
   python -m http.server 8000
   ```

3. Open browser:
   ```
   http://localhost:8000
   ```

The frontend will automatically connect to the backend at `http://localhost:5000`.

## Docker Deployment (Optional)

If using Docker:

```bash
# Build
docker build -t tor-unveil-backend ./backend

# Run
docker run -p 5000:5000 \
  -e API_KEY=changeme \
  -e TOR_CONTROL_HOST=host.docker.internal \
  tor-unveil-backend
```

## Monitoring & Logs

The backend provides detailed logging. Check console output for:

- Connection status
- Feature availability
- Request processing
- Errors and warnings

Example output:
```
======================================================================
TOR UNVEIL - Unified Backend v2.0
======================================================================
API Server: http://0.0.0.0:5000
Tor Control: 127.0.0.1:9051
API Key: changeme
======================================================================
Features:
  ✓ stem
  ✓ scapy
  ✓ dpkt
  ✓ sklearn
  ✓ reportlab
======================================================================
Connecting to Tor ControlPort...
✓ Tor connection established
======================================================================
Starting Flask server...
======================================================================
```

## Next Steps

1. Review [API_DOCUMENTATION.md](API_DOCUMENTATION.md) for complete API reference
2. Explore the frontend integration
3. Customize configuration via environment variables
4. Set up production deployment with HTTPS
5. Implement rate limiting and additional security measures

## Support

For issues or questions:
- Check the logs for detailed error messages
- Review the API documentation
- Ensure all dependencies are installed
- Verify Tor Browser is running (for circuit features)
- Check network connectivity (for relay information)

## Quick Reference

| Feature | Endpoint | Auth Required |
|---------|----------|---------------|
| Health Check | `GET /api/health` | No |
| System Status | `GET /api/status` | Yes |
| Circuits | `GET /api/circuits` | Yes |
| Relays | `GET /api/relays` | Yes |
| Start Capture | `POST /api/sniffer/start` | Yes |
| Stop Capture | `POST /api/sniffer/stop` | Yes |
| Upload PCAP | `POST /api/pcap/upload` | Yes |
| Correlate | `POST /api/correlate` | Yes |
| Generate Report | `POST /api/reports/generate` | Yes |

Default API Key: `changeme` (change in production!)
