# 🎯 TOR UNVEIL - Phase 2 Complete

## Advanced TOR Network Deanonymization System with ML & GeoIP

![Version](https://img.shields.io/badge/version-2.0-blue)
![Python](https://img.shields.io/badge/python-3.8+-green)
![License](https://img.shields.io/badge/license-Research-orange)
![Status](https://img.shields.io/badge/status-Production--Ready-success)

---

## 🌟 What's New in Phase 2

### 🧠 Machine Learning Integration
- **Random Forest Classifier** for website fingerprinting
- **50+ websites** trained (Google, Facebook, Netflix, GitHub, etc.)
- **70-80% accuracy** on known sites
- Automatic fallback to rule-based classification

### 🌍 GeoIP Intelligence
- **Dual-mode geolocation**: MaxMind GeoLite2 + API fallback
- **City-level accuracy** with lat/long coordinates
- **Automatic IP caching** (1-hour TTL)
- **User location estimation** from entry node analysis

### 📁 PCAP Analysis
- **Drag & drop** file upload interface
- **Offline analysis** of historical captures
- **Live/Offline mode** toggle
- Browse existing files from storage

### 📄 PDF Report Generation
- **Professional reports** with ReportLab
- **Risk assessment** (LOW/MEDIUM/HIGH)
- **Comprehensive statistics** and recommendations
- **Legal disclaimers** and evidence chain

---

## 🚀 Quick Start

### Installation (One-Time)
```powershell
# Option 1: Automated installer
.\INSTALL_PHASE2.bat

# Option 2: Manual install
pip install -r requirements.txt
```

### Launch Application
```powershell
# Interactive launcher with menu
.\LAUNCH_PHASE2.bat

# Or manually:
start_backend.bat    # Terminal 1
open_dashboard.bat   # Terminal 2
```

### Access Dashboard
Open browser to: **http://localhost:3000**

---

## 📋 System Requirements

### Required
- **Python 3.8+** with pip
- **Node.js** (for dashboard server)
- **Windows OS** (Admin rights for packet capture)
- **2 GB RAM** minimum
- **1 GB disk space** for storage

### Python Dependencies
```
scapy>=2.5.0          # Packet capture
numpy>=1.24.0         # Numerical computing
requests>=2.31.0      # HTTP requests
```

### Optional (Enhanced Features)
```
scikit-learn>=1.3.0   # ML classification
geoip2>=4.7.0         # MaxMind database
reportlab>=4.0.0      # PDF generation
Pillow>=10.0.0        # Image processing
```

---

## 🎮 Usage Guide

### Live Deanonymization
1. Switch to **🔴 LIVE** mode
2. Click **"Start Capture"**
3. Browse through TOR network
4. Wait 60+ seconds (100+ packets)
5. Click **"Stop"** → **"Run Analysis"**
6. View correlation results

### Historical Analysis
1. Switch to **📁 OFFLINE** mode
2. Click **"Analyze PCAP File"**
3. Select existing or upload new PCAP
4. Click **"Analyze PCAP"**
5. View forensic timeline

### Generate Report
1. Complete correlation analysis
2. Navigate to **Reports** page
3. Click **"Export PDF"**
4. Download from `/reports/` folder

---

## 🧪 How It Works

### Correlation Process

```
┌─────────────────┐
│  Packet Capture │ ← Live/Offline
└────────┬────────┘
         │
    ┌────▼────────────────┐
    │  Extract Features   │
    │  • Timing patterns  │
    │  • Flow signatures  │
    │  • Packet sizes     │
    └────┬────────────────┘
         │
    ┌────▼──────────────────────┐
    │   Correlation Analysis    │
    ├───────────────────────────┤
    │  1. Timing Correlation    │
    │  2. Traffic Analysis      │
    │  3. Website Fingerprint   │
    │  4. Circuit Correlation   │
    └────┬──────────────────────┘
         │
    ┌────▼────────────────┐
    │   GeoIP Lookup      │
    │   • Entry nodes     │
    │   • Exit nodes      │
    │   • User location   │
    └────┬────────────────┘
         │
    ┌────▼────────────────┐
    │  Visualization      │
    │  • Network topology │
    │  • World map        │
    │  • Confidence bars  │
    └─────────────────────┘
```

### Algorithms

**1. Timing Correlation**
- Analyzes inter-packet delays
- Cross-correlates entry/exit timing
- Detects timing patterns with confidence scoring

**2. Traffic Analysis**
- Examines packet size distributions
- Tracks bidirectional flows
- Identifies unique traffic signatures

**3. Website Fingerprinting**
- Extracts 5-dimensional feature vectors
- ML classification (Random Forest)
- Fallback to rule-based matching

**4. Geo-Location**
- IP → City mapping via MaxMind/API
- Entry node analysis for user location
- Confidence radius calculation

---

## 🏗️ Architecture

### Frontend (Web Interface)
```
index.html                  # Main dashboard
├── main.js                 # Core functionality
├── correlation-dashboard.js # Real-time updates
├── pcap-upload-modal.js    # File upload
├── enhanced-topology.js    # Network visualization
├── geo-positioning.js      # Map display
└── stats-updater.js        # Live statistics
```

### Backend (Python Server)
```
backend/
├── working_backend.py           # HTTP API server
├── tor_correlation_engine.py    # ML correlation
├── packet_sniffer.py            # Live capture
├── pdf_report_generator.py      # Reports
└── GeoLite2-City.mmdb          # GeoIP DB (optional)
```

### Data Storage
```
pcap_storage/          # Captured PCAP files
reports/               # Generated PDF reports
```

---

## 📡 API Reference

### Correlation Endpoints
```http
GET  /api/correlation/run      # Execute correlation
GET  /api/correlation/results  # Get latest results
GET  /api/correlation/stats    # Statistics
POST /api/correlation/analyze-pcap  # Offline analysis
```

### GeoIP Endpoints
```http
GET  /api/geo/locations        # All geo-located IPs
GET  /api/geo/user-location    # Estimated user location
POST /api/geo/lookup           # Lookup specific IP
```

### PCAP Management
```http
GET  /api/pcap/list            # List available files
POST /api/pcap/upload          # Upload new PCAP
```

### Reports
```http
GET  /api/reports/list         # List PDF reports
POST /api/reports/generate-pdf # Generate report
GET  /api/reports/download/:file  # Download report
```

---

## 🎨 Dashboard Features

### Control Panel
- **Mode Toggle**: Live ↔ Offline switching
- **TOR Controls**: Connect/disconnect
- **Capture Controls**: Start/stop sniffing
- **PCAP Upload**: Drag & drop interface

### Correlation Display
- **4 Confidence Meters**: Real-time progress bars
- **Strength Indicator**: LOW/MEDIUM/HIGH
- **Auto-Correlation**: Continuous monitoring toggle

### Visualizations
- **Network Topology**: Interactive node graph
- **Geo-Map**: World map with node locations
- **Live Packets**: Real-time packet stream
- **Statistics**: Bandwidth, circuits, threats

---

## 🔐 Security & Legal

### ⚠️ Critical Warnings

**Legal Requirements:**
- ✅ Obtain proper authorization before use
- ✅ Comply with local surveillance laws
- ✅ Document chain of custody
- ✅ Use only for authorized research/law enforcement

**Security Considerations:**
- 🔒 Run backend as Administrator
- 🔒 Never deploy on public networks
- 🔒 Secure all PCAP files and reports
- 🔒 Log all operations for audit trail

**Ethical Use:**
- ⚖️ TOR deanonymization is a sensitive capability
- ⚖️ Respect privacy and human rights
- ⚖️ Follow your organization's guidelines
- ⚖️ Consult legal counsel before deployment

---

## 📊 Performance Metrics

### System Performance
| Metric | Live Mode | Offline Mode |
|--------|-----------|--------------|
| CPU Usage | 15-25% | 10-15% |
| Memory | 200-400 MB | 150-300 MB |
| Packet Rate | 10K/sec | N/A |
| Analysis Time | Real-time | 2-30 seconds |

### Accuracy Benchmarks
| Feature | Accuracy | Notes |
|---------|----------|-------|
| Timing Correlation | 70-85% | Requires 100+ packets |
| Website Fingerprint | 70-80% | ML mode, 50+ sites |
| Geo-Location | ±10-50km | Depends on source |
| User Location | 60-70% | Medium confidence |

---

## 🐛 Troubleshooting

### Common Issues

**Backend won't start**
```powershell
# Solution: Run as Administrator
Right-click → Run as Administrator
```

**"Scapy not available"**
```powershell
pip install scapy
```

**Low correlation confidence**
- Capture more packets (min 100)
- Extend capture time (60+ seconds)
- Verify TOR traffic is present

**GeoIP lookups failing**
- Download GeoLite2 database
- Check internet connection (API mode)
- Wait for rate limit reset (1-2 minutes)

**PCAP analysis failed**
- Ensure file contains IP packets
- Check file permissions
- Verify file size < 1 GB

---

## 📚 Documentation

### Quick Guides
- `QUICK_REFERENCE.md` - Cheat sheet for operators
- `PHASE2_SETUP.md` - Complete setup instructions
- `IMPLEMENTATION_COMPLETE.md` - Technical details

### Test Scripts
- `INSTALL_PHASE2.bat` - Install dependencies
- `TEST_SYSTEM_PHASE2.bat` - System diagnostics
- `LAUNCH_PHASE2.bat` - Interactive launcher

---

## 🎓 Training Resources

### For Investigators
1. Review correlation confidence levels
2. Understand limitations and accuracy
3. Practice with test PCAP files
4. Learn to interpret geo-location results
5. Study legal requirements

### For Developers
1. Extend `website_db` with more sites
2. Customize PDF report templates
3. Add new correlation algorithms
4. Integrate with external databases
5. Enhance ML models

---

## 🚧 Known Limitations

1. **Website Fingerprinting**: Limited to 50 trained sites
2. **GeoIP API**: Free tier rate-limited (45 req/min)
3. **Timing Correlation**: Requires significant packet volume
4. **User Location**: Medium confidence, not definitive
5. **TOR Detection**: Heuristic-based, may miss obfuscation

---

## 🔮 Future Enhancements

### Planned (Phase 3+)
- [ ] Deep learning (CNN/LSTM) for fingerprinting
- [ ] Real-time alerting and notifications
- [ ] PostgreSQL database integration
- [ ] Multi-user authentication system
- [ ] Advanced pattern recognition
- [ ] Threat intelligence feed integration
- [ ] Blockchain transaction tracking
- [ ] Dark web marketplace monitoring

---

## 📞 Support

### Getting Help
1. Check `QUICK_REFERENCE.md` for quick answers
2. Run `TEST_SYSTEM_PHASE2.bat` for diagnostics
3. Review backend logs for errors
4. Check browser console (F12)
5. Verify all dependencies installed

### Reporting Issues
- Document error messages
- Include system configuration
- Provide PCAP file size/format
- Note Python/Node.js versions

---

## 👨‍💻 Credits

**Creator:** MOHAMMED ZUHAIB  
**Project:** TOR Unveil Phase 2  
**Version:** 2.0  
**Date:** December 2025  
**Purpose:** Research & Law Enforcement Tool

### Technologies Used
- **Backend**: Python 3.8+, HTTP Server, Scapy
- **Frontend**: HTML5, JavaScript, ECharts, Tailwind CSS
- **ML**: scikit-learn (Random Forest)
- **GeoIP**: MaxMind GeoLite2, ip-api.com
- **Reports**: ReportLab (PDF generation)

---

## 📜 License

**Research & Educational Use Only**

This tool is provided for:
- Academic research
- Authorized law enforcement operations
- Cybersecurity training and education

**NOT authorized for:**
- Unauthorized surveillance
- Privacy violations
- Malicious purposes
- Public deployment

Use of this tool must comply with all applicable laws and regulations.

---

## ⭐ Acknowledgments

Special thanks to:
- TOR Project for network research
- MaxMind for GeoLite2 database
- scikit-learn community
- Scapy developers
- Open source security community

---

## 📞 Contact & Feedback

For questions, suggestions, or collaboration:
- Review documentation thoroughly first
- Test with provided scripts
- Document any issues clearly
- Respect legal and ethical guidelines

---

**⚠️ IMPORTANT LEGAL NOTICE**

This system is designed for authorized use only. Unauthorized monitoring, interception, or deanonymization of network traffic may violate:
- Computer Fraud and Abuse Act (CFAA)
- Electronic Communications Privacy Act (ECPA)
- General Data Protection Regulation (GDPR)
- Local privacy and surveillance laws

**Always obtain proper legal authorization before deploying this system.**

---

*Last Updated: December 19, 2025*  
*Version 2.0 - Phase 2 Complete*

**🎉 Ready to unveil the TOR network!**
