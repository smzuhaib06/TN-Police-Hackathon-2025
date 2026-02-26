import requests
import sys
fn = 'pcap_storage\\capture_20251213T061609Z.pcap'
url = 'http://127.0.0.1:5000/api/pcap/upload'
with open(fn, 'rb') as f:
    files = {'file': ('capture.pcap', f, 'application/vnd.tcpdump.pcap')}
    r = requests.post(url, files=files, headers={'X-API-Key': 'changeme'})
    print('STATUS', r.status_code)
    try:
        print(r.json())
    except Exception:
        print(r.text)
