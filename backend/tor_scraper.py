"""
Web Scraper for TOR Node Information
Fetches accurate TOR relay information from Onionoo and TOR Project APIs
"""

import json
import requests
import logging
import time
from datetime import datetime
from typing import Dict, List
import threading
from collections import defaultdict

logging.getLogger(__name__).addHandler(logging.NullHandler())

def _get_with_retries(session, url, params=None, timeout=10, attempts=3, backoff=1.5):
    last_exc = None
    for attempt in range(1, attempts + 1):
        try:
            resp = session.get(url, params=params, timeout=timeout)
            resp.raise_for_status()
            return resp
        except Exception as e:
            last_exc = e
            wait = backoff ** (attempt - 1)
            logging.warning(f"GET {url} failed (attempt {attempt}/{attempts}): {e}; retrying in {wait}s")
            time.sleep(wait)
    # final attempt without catching to raise
    raise last_exc

class TORNodeScraper:
    """Scrapes TOR relay information from Onionoo and TOR Project"""
    
    # Official APIs
    ONIONOO_API = "https://onionoo.torproject.org"
    TOR_METRICS_API = "https://metrics.torproject.org"
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'TOR-Unveil/1.0 (Forensic Analysis Tool)'
        })
        self.node_cache = {}
        self.cache_time = {}
        self.lock = threading.Lock()
    
    def fetch_all_relays(self) -> Dict:
        """Fetch all active TOR relays from Onionoo"""
        try:
            response = _get_with_retries(self.session, f"{self.ONIONOO_API}/summary", timeout=12, attempts=4)
            return response.json()
        except Exception as e:
            logging.error(f"Error fetching relays after retries: {e}")
            return {}
    
    def fetch_relay_details(self, fingerprint: str) -> Dict:
        """Fetch detailed information about a specific relay"""
        try:
            response = _get_with_retries(self.session, f"{self.ONIONOO_API}/details", params={'lookup': fingerprint}, timeout=12, attempts=4)
            data = response.json()
            if data.get('relays'):
                return data['relays'][0]
            return {}
        except Exception as e:
            logging.error(f"Error fetching relay details for {fingerprint}: {e}")
            return {}
    
    def fetch_exit_nodes(self) -> List[Dict]:
        """Fetch list of exit nodes"""
        try:
            relays_data = self.fetch_all_relays()
            exit_nodes = []
            for relay in relays_data.get('relays', []):
                flags = (relay.get('r') or [{}])[0].get('flags', [])
                if 'Exit' in flags:
                    exit_nodes.append({
                        'nickname': relay.get('n'),
                        'fingerprint': relay.get('f'),
                        'first_seen': relay.get('a_first', ''),
                        'last_seen': relay.get('a_last', ''),
                        'addresses': relay.get('a', []),
                        'flags': flags,
                        'bandwidth': relay.get('bw', 0),
                        'country': relay.get('c', 'Unknown'),
                        'as': relay.get('as', '')
                    })
            return exit_nodes
        except Exception as e:
            logging.error(f"Error fetching exit nodes: {e}")
            return []
    
    def fetch_guard_nodes(self) -> List[Dict]:
        """Fetch list of guard nodes"""
        try:
            relays_data = self.fetch_all_relays()
            guard_nodes = []
            for relay in relays_data.get('relays', []):
                flags = (relay.get('r') or [{}])[0].get('flags', [])
                if 'Guard' in flags:
                    guard_nodes.append({
                        'nickname': relay.get('n'),
                        'fingerprint': relay.get('f'),
                        'first_seen': relay.get('a_first', ''),
                        'last_seen': relay.get('a_last', ''),
                        'addresses': relay.get('a', []),
                        'flags': flags,
                        'bandwidth': relay.get('bw', 0),
                        'country': relay.get('c', 'Unknown'),
                        'as': relay.get('as', '')
                    })
            return guard_nodes
        except Exception as e:
            logging.error(f"Error fetching guard nodes: {e}")
            return []
    
    def fetch_relay_by_ip(self, ip_address: str) -> Dict:
        """Search for relay by IP address"""
        try:
            response = _get_with_retries(self.session, f"{self.ONIONOO_API}/details", params={'lookup': ip_address}, timeout=12, attempts=4)
            data = response.json()
            if data.get('relays'):
                return data['relays'][0]
            return {}
        except Exception as e:
            logging.error(f"Error fetching relay by IP {ip_address}: {e}")
            return {}
    
    def fetch_bridge_relays(self) -> List[Dict]:
        """Fetch bridge relay information"""
        try:
            relays_data = self.fetch_all_relays()
            bridges = []
            for relay in relays_data.get('bridges', []):
                bridges.append({
                    'nickname': relay.get('n', 'Unknown'),
                    'hashed_fingerprint': relay.get('h', ''),
                    'first_seen': relay.get('first_seen', ''),
                    'last_seen': relay.get('last_seen', '')
                })
            return bridges
        except Exception as e:
            logging.error(f"Error fetching bridges: {e}")
            return []
    
    def fetch_network_statistics(self) -> Dict:
        """Fetch overall TOR network statistics"""
        try:
            relays = self.fetch_all_relays()
            exit_count = 0
            guard_count = 0
            middle_count = 0
            total_bandwidth = 0
            for relay in relays.get('relays', []):
                flags = (relay.get('r') or [{}])[0].get('flags', [])
                bandwidth = relay.get('bw', 0)
                total_bandwidth += bandwidth
                if 'Exit' in flags:
                    exit_count += 1
                if 'Guard' in flags:
                    guard_count += 1
                if flags and 'Exit' not in flags and 'Guard' not in flags:
                    middle_count += 1
            return {
                'total_relays': len(relays.get('relays', [])),
                'exit_nodes': exit_count,
                'guard_nodes': guard_count,
                'middle_relays': middle_count,
                'bridge_relays': len(relays.get('bridges', [])),
                'total_bandwidth': total_bandwidth,
                'fetch_time': datetime.now().isoformat()
            }
        except Exception as e:
            logging.error(f"Error fetching network statistics: {e}")
            return {}
    
    def correlate_ip_with_tor_nodes(self, ip_address: str) -> Dict:
        """Check if an IP is a known TOR relay"""
        try:
            with self.lock:
                # Check cache first
                if ip_address in self.node_cache:
                    return self.node_cache[ip_address]
            
            relay_info = self.fetch_relay_by_ip(ip_address)
            
            result = {
                'ip': ip_address,
                'is_tor_node': bool(relay_info),
                'relay_info': relay_info,
                'check_time': datetime.now().isoformat()
            }
            
            with self.lock:
                self.node_cache[ip_address] = result
            
            return result
        except Exception as e:
            return {
                'ip': ip_address,
                'is_tor_node': False,
                'error': str(e)
            }
    
    def get_node_characteristics(self, fingerprint: str) -> Dict:
        """Get detailed characteristics of a node for correlation"""
        try:
            relay = self.fetch_relay_details(fingerprint)
            
            if not relay:
                return {}
            
            return {
                'fingerprint': fingerprint,
                'nickname': relay.get('nickname', ''),
                'country': relay.get('country', ''),
                'country_name': relay.get('country_name', ''),
                'as_number': relay.get('as_number', ''),
                'as_name': relay.get('as_name', ''),
                'addresses': relay.get('addresses', []),
                'or_addresses': relay.get('or_addresses', []),
                'dir_addresses': relay.get('dir_addresses', []),
                'flags': relay.get('flags', []),
                'bandwidth': relay.get('bandwidth', 0),
                'advertised_bandwidth': relay.get('advertised_bandwidth', 0),
                'exit_policy': relay.get('exit_policy', []),
                'first_seen': relay.get('first_seen', ''),
                'last_seen': relay.get('last_seen', '')
            }
        except Exception as e:
            print(f"Error getting node characteristics: {e}")
            return {}
    
    def bulk_correlate_ips(self, ip_list: List[str]) -> Dict:
        """Correlate multiple IPs against TOR network"""
        results = {
            'tor_nodes': [],
            'unknown_ips': [],
            'check_time': datetime.now().isoformat()
        }
        for ip in ip_list:
            try:
                result = self.correlate_ip_with_tor_nodes(ip)
                if result.get('is_tor_node'):
                    results['tor_nodes'].append(result)
                else:
                    results['unknown_ips'].append(ip)
            except Exception as e:
                logging.warning(f"Bulk correlate: failed for {ip}: {e}")
                results['unknown_ips'].append(ip)
        return results
    
    def get_geographic_distribution(self) -> Dict:
        """Get geographic distribution of TOR nodes"""
        try:
            relays = self.fetch_all_relays()
            distribution = defaultdict(int)
            bandwidth_by_country = defaultdict(int)
            
            for relay in relays.get('relays', []):
                country = relay.get('c', 'Unknown')
                distribution[country] += 1
                bandwidth_by_country[country] += relay.get('bw', 0)
            
            return {
                'node_distribution': dict(distribution),
                'bandwidth_distribution': dict(bandwidth_by_country),
                'fetch_time': datetime.now().isoformat()
            }
        except Exception as e:
            print(f"Error getting geographic distribution: {e}")
            return {}
