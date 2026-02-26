# TOR-Unveil (TN Police Hackathon 2025)

TOR-Unveil is a toolkit for analyzing, correlating, and visualizing network traffic to detect and investigate Tor-related activity. It bundles packet capture ingestion, correlation engines, quick forensic reports, and interactive visualizations to help analysts and incident responders explore suspicious traffic.

**Key features**
- **PCAP ingestion**: Upload and process pcap files with parsing and cleanup tools.
- **Correlation engines**: Multiple correlation modules (including Tor-specific heuristics) to link related flows and events.
- **Visualization**: Interactive dashboards and topology maps for traffic and IP correlation.
- **Reports**: Generate forensic and professional PDF/HTML reports from analysis results.
- **Live sniffing**: Optional live packet capture components for near real-time monitoring.

**Repository structure**
- `backend/` : Core analysis modules, correlation engines, sniffers, and report generators.
- `resources/` : Supporting files and configuration (Tor, templates).
- `*.html`, `*.js` : Frontend dashboards and visualizations.
- `requirements.txt` : Python dependencies for backend components.

Getting started
1. Create a Python 3.9+ virtual environment and activate it:

	python3 -m venv venv
	source venv/bin/activate

2. Install dependencies:

	pip install -r requirements.txt

3. Run the frontend (simple static pages):

	python3 start_frontend.py

4. Run backend analysis on a pcap:

	python3 backend/upload_pcap.py path/to/capture.pcap

See `backend/` for more specialized scripts like `run_live_sniff.py`, `analyze_pcap_and_visualize.py`, and report generators.

Usage examples
- Quick report from a captured file:

  python3 backend/analyze_pcap_and_visualize.py --pcap captures/example.pcap --out reports/example_report.html

- Start live capture and basic correlation (requires privileges):

  sudo python3 backend/run_live_sniff.py --interface eth0

Development notes
- Many backend tools are script-based for easy integration; inspect `backend/` to find the script matching your workflow.
- To extend correlation logic, add or modify modules under `backend/correlation_engine.py` or `backend/tor_correlation_engine.py`.

Contributing
- Please open issues or pull requests for bug fixes and feature suggestions.
- Keep changes focused, include tests where appropriate, and update this README with usage or configuration changes.

License
This project is provided AS-IS for research and educational purposes; add a license file to clarify reuse terms.

Contact
For questions or help, open an issue on the repository or contact the maintainers listed in the project metadata.

