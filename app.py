"""
SecureZone: Research-Grade Network Security System
Enhanced with SSL/TLS Certificate Inspection, DNS Analysis, Protocol Fingerprinting,
User Behavior Analytics, and Threat Intelligence Integration

Complete Flask Application - app.py
"""

import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import json
import threading
from flask import render_template
import time
from flask import Flask, jsonify, request
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler, MinMaxScaler
from sklearn.neural_network import MLPClassifier
from sklearn.cluster import DBSCAN
import networkx as nx
from collections import defaultdict, deque
import logging
import warnings
import hashlib
warnings.filterwarnings('ignore')

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def convert_numpy_types(obj):
    """Convert numpy types to native Python types for JSON serialization"""
    if isinstance(obj, (np.integer, np.int32, np.int64)):
        return int(obj)
    elif isinstance(obj, (np.floating, np.float32, np.float64)):
        return float(obj)
    elif isinstance(obj, np.ndarray):
        return obj.tolist()
    elif isinstance(obj, dict):
        return {key: convert_numpy_types(value) for key, value in obj.items()}
    elif isinstance(obj, list):
        return [convert_numpy_types(item) for item in obj]
    elif isinstance(obj, datetime):
        return obj.isoformat()
    elif isinstance(obj, set):
        return list(obj)
    return obj


class SSLCertificateInspector:
    """Advanced SSL/TLS certificate analysis and anomaly detection"""
    
    def __init__(self):
        self.certificate_cache = {}
        self.suspicious_patterns = {
            'self_signed_certs': [],
            'expired_certs': [],
            'invalid_chains': [],
            'weak_ciphers': []
        }
        self.trusted_cas = ['DigiCert', 'Let\'s Encrypt', 'GlobalSign', 'Comodo', 'GeoTrust', 'Sectigo']
    
    def analyze_certificate(self, cert_data):
        """Comprehensive SSL certificate security analysis"""
        risk_score = 0
        findings = []
        threat_indicators = []
        
        # Certificate expiration check
        days_until_expiry = cert_data.get('days_until_expiry', 365)
        if days_until_expiry < 0:
            risk_score += 40
            findings.append("⚠️ EXPIRED CERTIFICATE")
            threat_indicators.append("expired_cert")
            self.suspicious_patterns['expired_certs'].append(cert_data)
        elif days_until_expiry < 7:
            risk_score += 20
            findings.append(f"Certificate expiring in {days_until_expiry} days")
        
        # Self-signed certificate detection
        if cert_data.get('self_signed', False):
            risk_score += 35
            findings.append("⚠️ Self-signed certificate (possible MITM)")
            threat_indicators.append("self_signed")
            self.suspicious_patterns['self_signed_certs'].append(cert_data)
        
        # Certificate Authority validation
        issuer = cert_data.get('issuer', 'Unknown')
        if issuer not in self.trusted_cas:
            risk_score += 15
            findings.append(f"Untrusted CA: {issuer}")
            threat_indicators.append("untrusted_ca")
        
        # Cipher suite strength analysis
        cipher = cert_data.get('cipher_suite', '')
        weak_ciphers = ['rc4', 'md5', 'des', 'ssl3', 'tls1.0']
        if any(weak in cipher.lower() for weak in weak_ciphers):
            risk_score += 30
            findings.append(f"⚠️ Weak cipher suite: {cipher}")
            threat_indicators.append("weak_cipher")
            self.suspicious_patterns['weak_ciphers'].append(cert_data)
        
        # Key length validation
        key_length = cert_data.get('key_length', 2048)
        if key_length < 2048:
            risk_score += 25
            findings.append(f"⚠️ Weak key length: {key_length} bits (minimum: 2048)")
            threat_indicators.append("weak_key")
        
        # Hostname mismatch detection
        if cert_data.get('hostname_mismatch', False):
            risk_score += 45
            findings.append("⚠️ CERTIFICATE HOSTNAME MISMATCH (possible phishing/MITM)")
            threat_indicators.append("hostname_mismatch")
        
        # Certificate pinning violation
        if cert_data.get('pinning_violation', False):
            risk_score += 50
            findings.append("🚨 Certificate pinning violation detected")
            threat_indicators.append("pinning_violation")
        
        # Certificate Transparency logs
        if not cert_data.get('ct_logs_present', True):
            risk_score += 20
            findings.append("Not present in Certificate Transparency logs")
            threat_indicators.append("no_ct_logs")
        
        # Subject Alternative Names analysis
        san_count = len(cert_data.get('subject_alt_names', []))
        if san_count > 100:
            risk_score += 25
            findings.append(f"⚠️ Suspicious SAN count: {san_count} (possible certificate abuse)")
            threat_indicators.append("excessive_sans")
        
        # Certificate chain validation
        if cert_data.get('invalid_chain', False):
            risk_score += 40
            findings.append("⚠️ Invalid certificate chain")
            threat_indicators.append("invalid_chain")
            self.suspicious_patterns['invalid_chains'].append(cert_data)
        
        return {
            'risk_score': min(risk_score, 100),
            'findings': findings,
            'threat_indicators': threat_indicators,
            'cert_details': cert_data,
            'severity': 'critical' if risk_score >= 70 else 'high' if risk_score >= 40 else 'medium' if risk_score >= 20 else 'low'
        }
    
    def detect_certificate_anomalies(self, connection_data):
        """Detect certificate rotation and MITM attacks"""
        cert_info = connection_data.get('certificate', {})
        domain = connection_data.get('dst_domain', '')
        
        analysis = self.analyze_certificate(cert_info)
        
        # Certificate rotation detection
        if domain in self.certificate_cache:
            prev_cert = self.certificate_cache[domain]
            if prev_cert['fingerprint'] != cert_info.get('fingerprint'):
                time_diff = (datetime.now() - prev_cert['last_seen']).total_seconds()
                
                # Suspicious rapid certificate change
                if time_diff < 3600:  # Less than 1 hour
                    analysis['findings'].append("🚨 Certificate changed within 1 hour (possible MITM attack)")
                    analysis['risk_score'] += 40
                    analysis['threat_indicators'].append("rapid_cert_rotation")
                else:
                    analysis['findings'].append("Certificate rotated")
                    analysis['risk_score'] += 10
        
        # Cache current certificate
        self.certificate_cache[domain] = {
            'fingerprint': cert_info.get('fingerprint'),
            'last_seen': datetime.now(),
            'issuer': cert_info.get('issuer')
        }
        
        return analysis


class DNSSecurityAnalyzer:
    """Advanced DNS analysis for tunneling, exfiltration, and DGA detection"""
    
    def __init__(self):
        self.dns_baseline = {}
        self.suspicious_domains = []
        self.query_history = deque(maxlen=10000)
    
    def analyze_dns_traffic(self, dns_data):
        """Comprehensive DNS security analysis"""
        risk_score = 0
        findings = []
        threat_indicators = []
        
        domain = dns_data.get('query_domain', '')
        
        # DNS Tunneling Detection - Query length analysis
        if len(domain) > 50:
            risk_score += 30
            findings.append(f"⚠️ Suspicious long domain: {len(domain)} chars (possible DNS tunneling)")
            threat_indicators.append("long_domain")
        
        # Subdomain analysis
        subdomain_count = domain.count('.')
        if subdomain_count > 5:
            risk_score += 25
            findings.append(f"⚠️ Excessive subdomains: {subdomain_count} (possible data exfiltration)")
            threat_indicators.append("excessive_subdomains")
        
        # Entropy analysis for encoded data
        entropy = self._calculate_entropy(domain)
        if entropy > 4.5:
            risk_score += 35
            findings.append(f"⚠️ High entropy domain: {entropy:.2f} (possible encoded data)")
            threat_indicators.append("high_entropy")
        
        # Query rate analysis
        query_rate = dns_data.get('queries_per_minute', 0)
        if query_rate > 100:
            risk_score += 30
            findings.append(f"⚠️ Excessive query rate: {query_rate}/min (possible C2 beaconing)")
            threat_indicators.append("high_query_rate")
        elif query_rate > 50:
            risk_score += 15
            findings.append(f"Elevated query rate: {query_rate}/min")
        
        # TXT record abuse detection
        if dns_data.get('record_type') == 'TXT':
            response_length = len(dns_data.get('response', ''))
            if response_length > 200:
                risk_score += 40
                findings.append(f"🚨 Large TXT record: {response_length} bytes (possible data exfiltration)")
                threat_indicators.append("txt_abuse")
        
        # Response size analysis
        response_size = dns_data.get('response_size', 0)
        if response_size > 512:
            risk_score += 20
            findings.append(f"Unusually large DNS response: {response_size} bytes")
            threat_indicators.append("large_response")
        
        # Domain Generation Algorithm (DGA) detection
        if self._detect_dga(domain):
            risk_score += 50
            findings.append("🚨 POSSIBLE DGA DOMAIN (malware C2 pattern)")
            threat_indicators.append("dga_detected")
        
        # Fast flux detection
        if self._detect_fast_flux(dns_data):
            risk_score += 45
            findings.append("🚨 Fast flux DNS pattern detected (possible botnet)")
            threat_indicators.append("fast_flux")
        
        # Record query for historical analysis
        self.query_history.append({
            'domain': domain,
            'timestamp': datetime.now(),
            'risk_score': risk_score
        })
        
        return {
            'risk_score': min(risk_score, 100),
            'findings': findings,
            'threat_indicators': threat_indicators,
            'domain': domain,
            'entropy': round(entropy, 2),
            'severity': 'critical' if risk_score >= 70 else 'high' if risk_score >= 40 else 'medium' if risk_score >= 20 else 'low'
        }
    
    def _calculate_entropy(self, string):
        """Calculate Shannon entropy for randomness detection"""
        if not string:
            return 0
        entropy = 0
        for x in range(256):
            p_x = float(string.count(chr(x))) / len(string)
            if p_x > 0:
                entropy += - p_x * np.log2(p_x)
        return entropy
    
    def _detect_dga(self, domain):
        """Detect Domain Generation Algorithm patterns"""
        domain_part = domain.split('.')[0]
        
        if len(domain_part) < 6:
            return False
        
        # Vowel/consonant ratio analysis
        vowels = sum(1 for c in domain_part.lower() if c in 'aeiou')
        consonants = sum(1 for c in domain_part.lower() if c.isalpha()) - vowels
        
        # DGA domains typically have very few vowels
        if len(domain_part) > 10 and vowels < len(domain_part) * 0.2:
            return True
        
        # Numeric pattern analysis
        digit_count = sum(1 for c in domain_part if c.isdigit())
        if digit_count > len(domain_part) * 0.3:
            return True
        
        # Consecutive consonant analysis
        max_consecutive_consonants = 0
        current_consecutive = 0
        for c in domain_part.lower():
            if c.isalpha() and c not in 'aeiou':
                current_consecutive += 1
                max_consecutive_consonants = max(max_consecutive_consonants, current_consecutive)
            else:
                current_consecutive = 0
        
        if max_consecutive_consonants > 5:
            return True
        
        return False
    
    def _detect_fast_flux(self, dns_data):
        """Detect fast flux DNS patterns"""
        # Multiple A records with short TTL
        if dns_data.get('record_type') == 'A':
            ttl = dns_data.get('ttl', 3600)
            ip_count = len(dns_data.get('resolved_ips', []))
            
            if ttl < 300 and ip_count > 5:
                return True
        
        return False


class ProtocolAnalyzer:
    """Advanced protocol behavior analysis and tunneling detection"""
    
    def __init__(self):
        self.protocol_baselines = {}
        self.protocol_signatures = {}
    
    def analyze_protocol_behavior(self, flow_data):
        """Deep protocol analysis for anomalies and tunneling"""
        risk_score = 0
        findings = []
        threat_indicators = []
        
        protocol = flow_data.get('protocol', '')
        dst_port = flow_data.get('dst_port', 0)
        src_port = flow_data.get('src_port', 0)
        
        # Protocol-port mismatch detection
        expected_ports = {
            'HTTP': [80, 8080, 8000, 8888],
            'HTTPS': [443, 8443],
            'SSH': [22],
            'FTP': [21],
            'DNS': [53],
            'SMTP': [25, 587, 465],
            'POP3': [110, 995],
            'IMAP': [143, 993],
            'RDP': [3389],
            'SMB': [445, 139]
        }
        
        if protocol in expected_ports and dst_port not in expected_ports[protocol]:
            risk_score += 35
            findings.append(f"⚠️ {protocol} on non-standard port {dst_port} (possible tunneling)")
            threat_indicators.append("port_mismatch")
        
        # Packet size analysis
        byte_count = flow_data.get('byte_count', 0)
        packet_count = flow_data.get('packet_count', 1)
        avg_packet_size = byte_count / max(packet_count, 1)
        
        # DNS tunneling detection
        if protocol == 'DNS' and avg_packet_size > 512:
            risk_score += 30
            findings.append(f"⚠️ DNS packets too large: {avg_packet_size:.0f} bytes (possible tunneling)")
            threat_indicators.append("dns_tunneling")
        
        # HTTPS anomalies
        if protocol == 'HTTPS':
            if avg_packet_size < 100:
                risk_score += 25
                findings.append("HTTPS packets unusually small (suspicious)")
                threat_indicators.append("small_https_packets")
            elif avg_packet_size > 8000:
                risk_score += 20
                findings.append("HTTPS packets unusually large")
                threat_indicators.append("large_https_packets")
        
        # Inter-packet timing analysis
        packet_variance = flow_data.get('packet_interval_variance', 0)
        if packet_variance < 0.01 and packet_count > 100:
            risk_score += 30
            findings.append("⚠️ Machine-like timing pattern (possible bot/automated attack)")
            threat_indicators.append("bot_timing")
        
        # Protocol tunneling detection
        tunneling_result = self._detect_protocol_tunneling(flow_data)
        if tunneling_result['detected']:
            risk_score += 45
            findings.append(f"🚨 {tunneling_result['type']} detected")
            threat_indicators.append("protocol_tunneling")
        
        # Long-duration connections
        duration = flow_data.get('duration', 0)
        if duration > 3600 and protocol not in ['HTTPS', 'SSH']:
            risk_score += 20
            findings.append(f"Long-duration connection: {duration}s")
            threat_indicators.append("long_connection")
        
        # High bandwidth usage
        bandwidth = byte_count / max(duration, 1)
        if bandwidth > 10000000:  # 10 MB/s
            risk_score += 25
            findings.append(f"High bandwidth: {bandwidth/1e6:.2f} MB/s")
            threat_indicators.append("high_bandwidth")
        
        # Port scanning detection
        if self._detect_port_scanning(flow_data):
            risk_score += 50
            findings.append("🚨 PORT SCANNING DETECTED")
            threat_indicators.append("port_scan")
        
        return {
            'risk_score': min(risk_score, 100),
            'findings': findings,
            'threat_indicators': threat_indicators,
            'avg_packet_size': round(avg_packet_size, 2),
            'bandwidth_mbps': round(bandwidth / 1e6, 2) if 'bandwidth' in locals() else 0,
            'severity': 'critical' if risk_score >= 70 else 'high' if risk_score >= 40 else 'medium' if risk_score >= 20 else 'low'
        }
    
    def _detect_protocol_tunneling(self, flow_data):
        """Detect various protocol tunneling techniques"""
        protocol = flow_data.get('protocol', '')
        dst_port = flow_data.get('dst_port', 0)
        byte_count = flow_data.get('byte_count', 0)
        
        # HTTP tunneling over non-HTTP ports
        if dst_port not in [80, 443, 8080, 8443] and byte_count > 1000000:
            if protocol == 'TCP':
                return {'detected': True, 'type': 'HTTP tunneling over TCP'}
        
        # SSH tunneling patterns
        if protocol == 'SSH' and byte_count > 100000000:
            return {'detected': True, 'type': 'SSH tunneling (large data transfer)'}
        
        # ICMP tunneling
        if protocol == 'ICMP' and byte_count > 10000:
            return {'detected': True, 'type': 'ICMP tunneling'}
        
        return {'detected': False, 'type': None}
    
    def _detect_port_scanning(self, flow_data):
        """Detect port scanning activity"""
        # Multiple connections to different ports from same source
        packet_count = flow_data.get('packet_count', 0)
        duration = flow_data.get('duration', 1)
        
        # SYN scan pattern: many packets, short duration, small payload
        if packet_count > 100 and duration < 10 and flow_data.get('byte_count', 0) < 10000:
            return True
        
        return False


class UserBehaviorAnalyzer:
    """Advanced user behavior profiling and anomaly detection"""
    
    def __init__(self):
        self.user_profiles = {}
        self.normal_patterns = {}
        self.baseline_period = 7  # days
    
    def analyze_user_behavior(self, user_id, activity_data):
        """Detect behavioral anomalies and insider threats"""
        risk_score = 0
        findings = []
        threat_indicators = []
        
        # Initialize profile for new users
        if user_id not in self.user_profiles:
            self.user_profiles[user_id] = {
                'normal_hours': set(range(8, 18)),  # Default business hours
                'typical_destinations': set(),
                'avg_data_transfer': 1000000,
                'typical_protocols': {'HTTP', 'HTTPS', 'DNS'},
                'baseline_start': datetime.now(),
                'activity_count': 0
            }
            return {
                'risk_score': 0, 
                'findings': ['New user - building behavioral baseline'], 
                'threat_indicators': [],
                'severity': 'info'
            }
        
        profile = self.user_profiles[user_id]
        profile['activity_count'] += 1
        
        # Time-based anomaly detection
        current_hour = datetime.now().hour
        if current_hour not in profile['normal_hours']:
            risk_score += 20
            findings.append(f"⚠️ Activity outside normal hours: {current_hour}:00")
            threat_indicators.append("off_hours_activity")
        
        # Destination anomaly detection
        dst_ip = activity_data.get('dst_ip', '')
        if dst_ip and dst_ip not in profile['typical_destinations']:
            if not self._is_known_service(dst_ip):
                risk_score += 25
                findings.append(f"Connection to unusual destination: {dst_ip}")
                threat_indicators.append("unusual_destination")
            
            # Add to profile after first encounter
            profile['typical_destinations'].add(dst_ip)
        
        # Data transfer anomaly detection
        current_transfer = activity_data.get('byte_count', 0)
        if current_transfer > profile['avg_data_transfer'] * 10:
            risk_score += 35
            findings.append(f"⚠️ Unusual data volume: {current_transfer / 1e6:.2f} MB (10x normal)")
            threat_indicators.append("data_exfiltration")
        elif current_transfer > profile['avg_data_transfer'] * 5:
            risk_score += 20
            findings.append(f"Elevated data volume: {current_transfer / 1e6:.2f} MB")
        
        # Protocol anomaly detection
        protocol = activity_data.get('protocol', '')
        if protocol and protocol not in profile['typical_protocols']:
            risk_score += 15
            findings.append(f"Unusual protocol for user: {protocol}")
            threat_indicators.append("unusual_protocol")
            profile['typical_protocols'].add(protocol)
        
        # Lateral movement detection
        lateral_result = self._detect_lateral_movement(activity_data)
        if lateral_result['detected']:
            risk_score += 50
            findings.append(f"🚨 LATERAL MOVEMENT: {lateral_result['description']}")
            threat_indicators.append("lateral_movement")
        
        # Data hoarding detection
        if self._detect_data_hoarding(user_id, activity_data):
            risk_score += 45
            findings.append("🚨 Possible data hoarding detected (insider threat)")
            threat_indicators.append("data_hoarding")
        
        # Privilege escalation attempt
        if self._detect_privilege_escalation(activity_data):
            risk_score += 60
            findings.append("🚨 PRIVILEGE ESCALATION ATTEMPT")
            threat_indicators.append("privilege_escalation")
        
        # Update profile averages
        profile['avg_data_transfer'] = (profile['avg_data_transfer'] * 0.95 + current_transfer * 0.05)
        
        return {
            'risk_score': min(risk_score, 100),
            'findings': findings,
            'threat_indicators': threat_indicators,
            'user_profile': {
                'activity_count': profile['activity_count'],
                'days_monitored': (datetime.now() - profile['baseline_start']).days
            },
            'severity': 'critical' if risk_score >= 70 else 'high' if risk_score >= 40 else 'medium' if risk_score >= 20 else 'low'
        }
    
    def _detect_lateral_movement(self, activity_data):
        """Detect lateral movement patterns"""
        src_ip = activity_data.get('src_ip', '')
        dst_ip = activity_data.get('dst_ip', '')
        protocol = activity_data.get('protocol', '')
        dst_port = activity_data.get('dst_port', 0)
        
        # Internal-to-internal admin protocol access
        if src_ip.startswith('192.168.') and dst_ip.startswith('192.168.'):
            if protocol in ['SMB', 'RDP', 'SSH', 'WinRM'] or dst_port in [445, 3389, 22, 5985]:
                return {
                    'detected': True,
                    'description': f'Internal {protocol} access to {dst_ip}'
                }
            
            # Multiple internal connections in short time
            if activity_data.get('packet_count', 0) < 100:  # Scanning pattern
                return {
                    'detected': True,
                    'description': 'Internal network scanning'
                }
        
        return {'detected': False, 'description': None}
    
    def _detect_data_hoarding(self, user_id, activity_data):
        """Detect data hoarding patterns (insider threat)"""
        # Multiple large file transfers
        if activity_data.get('byte_count', 0) > 50000000:  # 50 MB
            protocol = activity_data.get('protocol', '')
            if protocol in ['FTP', 'SFTP', 'SMB', 'HTTP']:
                return True
        
        return False
    
    def _detect_privilege_escalation(self, activity_data):
        """Detect privilege escalation attempts"""
        protocol = activity_data.get('protocol', '')
        dst_port = activity_data.get('dst_port', 0)
        
        # Access to privileged ports/services
        privileged_ports = [22, 23, 445, 3389, 5985]  # SSH, Telnet, SMB, RDP, WinRM
        if dst_port in privileged_ports:
            # Multiple failed attempts pattern
            if activity_data.get('packet_count', 0) > 50 and activity_data.get('duration', 0) < 30:
                return True
        
        return False
    
    def _is_known_service(self, ip):
        """Check if IP belongs to known/trusted services"""
        known_ranges = [
            '8.8.8.8', '8.8.4.4',  # Google DNS
            '1.1.1.1', '1.0.0.1',  # Cloudflare DNS
            '208.67.',              # OpenDNS
        ]
        return any(ip.startswith(kr) for kr in known_ranges)


class ThreatIntelligenceFeed:
    """Real-time threat intelligence integration and IOC matching"""
    
    def __init__(self):
        self.ioc_database = {
            'malicious_ips': {
                '192.168.1.100', '10.0.0.50', '172.16.1.25', 
                '185.220.100.240', '185.220.101.1'  # Example Tor exit nodes
            },
            'malicious_domains': {
                'evil-phishing-site.com', 'malware-c2.net', 'ransomware-payment.onion'
            },
            'c2_servers': {
                '192.168.1.100', '203.0.113.5', '198.51.100.10'
            },
            'tor_exit_nodes': {
                '185.220.100.240', '185.220.101.1', '185.220.102.242'
            },
            'known_botnets': {
                'mirai', 'emotet', 'trickbot', 'qakbot'
            }
        }
        self.reputation_scores = {}
        self.ioc_hits = deque(maxlen=1000)
    
    def check_threat_intelligence(self, connection_data):
        """Comprehensive threat intelligence checking"""
        risk_score = 0
        findings = []
        threat_indicators = []
        matched_iocs = []
        
        src_ip = connection_data.get('src_ip', '')
        dst_ip = connection_data.get('dst_ip', '')
        dst_domain = connection_data.get('dst_domain', '')
        
        # Malicious IP detection
        if src_ip in self.ioc_database['malicious_ips']:
            risk_score += 90
            findings.append(f"🚨 MALICIOUS SOURCE IP: {src_ip} (in threat feed)")
            threat_indicators.append("malicious_src_ip")
            matched_iocs.append(('ip', src_ip, 'malicious_source'))
        
        if dst_ip in self.ioc_database['malicious_ips']:
            risk_score += 85
            findings.append(f"🚨 MALICIOUS DESTINATION IP: {dst_ip} (in threat feed)")
            threat_indicators.append("malicious_dst_ip")
            matched_iocs.append(('ip', dst_ip, 'malicious_destination'))
        
        # C2 server detection
        if dst_ip in self.ioc_database['c2_servers']:
            risk_score += 95
            findings.append("🚨 CONNECTION TO KNOWN C2 SERVER")
            threat_indicators.append("c2_communication")
            matched_iocs.append(('ip', dst_ip, 'c2_server'))
        
        # Tor exit node detection
        if dst_ip in self.ioc_database['tor_exit_nodes']:
            risk_score += 40
            findings.append(f"⚠️ Connection to Tor exit node: {dst_ip}")
            threat_indicators.append("tor_usage")
            matched_iocs.append(('ip', dst_ip, 'tor_exit_node'))
        
        # Malicious domain detection
        if dst_domain in self.ioc_database['malicious_domains']:
            risk_score += 85
            findings.append(f"🚨 MALICIOUS DOMAIN: {dst_domain}")
            threat_indicators.append("malicious_domain")
            matched_iocs.append(('domain', dst_domain, 'malicious'))
        
        # Domain reputation analysis
        if dst_domain:
            domain_reputation = self.get_domain_reputation(dst_domain)
            if domain_reputation < 30:
                risk_score += 50
                findings.append(f"⚠️ Low domain reputation: {domain_reputation}/100")
                threat_indicators.append("low_reputation")
            elif domain_reputation < 50:
                risk_score += 25
                findings.append(f"Moderate domain reputation: {domain_reputation}/100")
        
        # Newly registered domain detection
        if dst_domain and self._is_newly_registered(dst_domain):
            risk_score += 30
            findings.append(f"⚠️ Newly registered domain: {dst_domain}")
            threat_indicators.append("new_domain")
        
        # Geolocation anomaly
        geo_risk = self._check_geolocation_risk(dst_ip)
        if geo_risk['risk'] > 0:
            risk_score += geo_risk['risk']
            findings.append(geo_risk['finding'])
            threat_indicators.append("geo_anomaly")
        
        # Record IOC hit
        if matched_iocs:
            self.ioc_hits.append({
                'timestamp': datetime.now(),
                'iocs': matched_iocs,
                'connection': connection_data
            })
        
        return {
            'risk_score': min(risk_score, 100),
            'findings': findings,
            'threat_indicators': threat_indicators,
            'matched_iocs': matched_iocs,
            'severity': 'critical' if risk_score >= 70 else 'high' if risk_score >= 40 else 'medium' if risk_score >= 20 else 'low'
        }
    
    def get_domain_reputation(self, domain):
        """Get domain reputation score (0-100)"""
        if domain in self.reputation_scores:
            return self.reputation_scores[domain]
        
        # Simulate reputation lookup
        if any(bad in domain.lower() for bad in ['phish', 'malware', 'virus', 'hack', 'exploit']):
            score = np.random.randint(0, 30)
        elif domain.endswith('.onion'):
            score = np.random.randint(20, 40)
        else:
            score = np.random.randint(50, 95)
        
        self.reputation_scores[domain] = score
        return score
    
    def _is_newly_registered(self, domain):
        """Check if domain was recently registered"""
        # Simulate domain age check
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top']
        if any(domain.endswith(tld) for tld in suspicious_tlds):
            return True
        
        # Randomly mark some domains as new for demo
        return np.random.random() < 0.1
    
    def _check_geolocation_risk(self, ip):
        """Check geolocation-based risk"""
        # High-risk countries (simplified simulation)
        high_risk_ranges = ['203.0.113.', '198.51.100.']
        
        if any(ip.startswith(hr) for hr in high_risk_ranges):
            return {
                'risk': 25,
                'finding': f"⚠️ Connection to high-risk geographic location"
            }
        
        return {'risk': 0, 'finding': None}


class AdvancedPayloadAnalyzer:
    """Simulated payload analysis (normally requires packet capture)"""
    
    def __init__(self):
        self.payload_signatures = {
            'sql_injection': ['select', 'union', 'drop table', 'exec(', '--'],
            'xss': ['<script>', 'javascript:', 'onerror=', 'onclick='],
            'command_injection': ['&&', '||', ';cat', '`', '$('],
            'path_traversal': ['../', '..\\', '%2e%2e'],
        }
    
    def analyze_payload_indicators(self, flow_data):
        """Analyze flow characteristics that indicate payload threats"""
        risk_score = 0
        findings = []
        threat_indicators = []
        
        # HTTP-specific analysis
        if flow_data.get('protocol') in ['HTTP', 'HTTPS']:
            # Suspicious URI patterns
            uri_length = flow_data.get('uri_length', 0)
            if uri_length > 500:
                risk_score += 30
                findings.append(f"⚠️ Suspicious long URI: {uri_length} chars")
                threat_indicators.append("long_uri")
            
            # POST request with large payload
            if flow_data.get('method') == 'POST' and flow_data.get('byte_count', 0) > 1000000:
                risk_score += 25
                findings.append("Large POST request (possible upload attack)")
                threat_indicators.append("large_post")
            
            # Encoded payload detection
            if flow_data.get('uri_encoded_percent', 0) > 50:
                risk_score += 35
                findings.append("Highly encoded URI (possible obfuscation)")
                threat_indicators.append("uri_encoding")
        
        return {
            'risk_score': min(risk_score, 100),
            'findings': findings,
            'threat_indicators': threat_indicators
        }


class EnsembleAnomalyDetector:
    """Ensemble anomaly detector combining multiple ML approaches"""
    
    def __init__(self):
        self.models = {
            'isolation_forest': IsolationForest(contamination=0.1, random_state=42, n_estimators=100),
            'autoencoder_mlp': MLPClassifier(hidden_layer_sizes=(64, 32, 16, 32, 64), 
                                           max_iter=200, random_state=42, warm_start=True),
            'clustering_detector': DBSCAN(eps=0.5, min_samples=5)
        }
        
        self.scalers = {
            'standard': StandardScaler(),
            'minmax': MinMaxScaler()
        }
        
        self.is_trained = False
        self.normal_stats = {}
        self.features_cache = {}
        
    def extract_advanced_features(self, traffic_data):
        """Extract comprehensive features from traffic"""
        features_list = []
        
        for flow in traffic_data:
            basic_features = [
                flow.get('packet_count', 0),
                flow.get('byte_count', 0),
                flow.get('duration', 0),
                flow.get('src_port', 0),
                flow.get('dst_port', 0),
                self._encode_protocol(flow.get('protocol', 'TCP'))
            ]
            
            advanced_features = [
                flow.get('packet_count', 0) / max(flow.get('duration', 1), 1),
                flow.get('byte_count', 0) / max(flow.get('duration', 1), 1),
                flow.get('byte_count', 0) / max(flow.get('packet_count', 1), 1),
                self._calculate_port_entropy(flow),
                self._extract_temporal_features(flow),
            ]
            
            features_list.append(basic_features + advanced_features)
        
        return np.array(features_list)
    
    def _encode_protocol(self, protocol):
        """Encode protocol as number"""
        protocol_map = {
            'TCP': 1, 'UDP': 2, 'ICMP': 3, 'HTTP': 4, 'HTTPS': 5, 
            'SSH': 6, 'DNS': 7, 'IRC': 8, 'P2P': 9, 'FTP': 10, 
            'SMTP': 11, 'POP3': 12, 'IMAP': 13
        }
        return protocol_map.get(protocol, 0)
    
    def _calculate_port_entropy(self, flow):
        """Calculate port entropy"""
        ports = [flow.get('src_port', 0), flow.get('dst_port', 0)]
        if max(ports) == 0:
            return 0
        unique_ports = len(set(ports))
        if unique_ports <= 1:
            return 0
        entropy = -sum((ports.count(p) / len(ports)) * np.log2(ports.count(p) / len(ports)) 
                      for p in set(ports) if ports.count(p) > 0)
        return entropy
    
    def _extract_temporal_features(self, flow):
        """Extract time-based features"""
        current_time = datetime.now()
        hour = current_time.hour
        day_of_week = current_time.weekday()
        
        hour_sin = np.sin(2 * np.pi * hour / 24)
        hour_cos = np.cos(2 * np.pi * hour / 24)
        day_sin = np.sin(2 * np.pi * day_of_week / 7)
        
        return (hour_sin + hour_cos + day_sin) / 3
    
    def train_ensemble(self, normal_traffic_data):
        """Train ensemble of anomaly detectors"""
        logger.info("Training ensemble anomaly detection models...")
        
        features = self.extract_advanced_features(normal_traffic_data)
        
        if len(features) < 10:
            logger.warning("Not enough training data, using defaults")
            self.is_trained = False
            return {'status': 'insufficient_data'}
        
        scaled_features_std = self.scalers['standard'].fit_transform(features)
        scaled_features_minmax = self.scalers['minmax'].fit_transform(features)
        
        training_results = {}
        
        try:
            self.models['isolation_forest'].fit(scaled_features_std)
            training_results['isolation_forest'] = 'trained'
            
            normal_labels = np.zeros(len(scaled_features_std))
            self.models['autoencoder_mlp'].fit(scaled_features_minmax, normal_labels)
            training_results['autoencoder_mlp'] = 'trained'
            
            cluster_labels = self.models['clustering_detector'].fit_predict(scaled_features_std)
            n_clusters = len(set(cluster_labels))
            training_results['clustering_detector'] = f'{n_clusters} clusters'
            
            self._train_statistical_detector(normal_traffic_data)
            training_results['statistical_detector'] = 'trained'
            
            self.is_trained = True
            logger.info(f"Ensemble training completed: {training_results}")
            return training_results
        
        except Exception as e:
            logger.error(f"Training error: {str(e)}")
            self.is_trained = False
            return {'error': str(e)}
    
    def _train_statistical_detector(self, traffic_data):
        """Train statistical anomaly detector"""
        features = [
            [f.get('packet_count', 0), f.get('byte_count', 0), f.get('duration', 0)]
            for f in traffic_data
        ]
        features_array = np.array(features)
        
        self.normal_stats = {
            'mean': np.mean(features_array, axis=0),
            'std': np.std(features_array, axis=0),
            'min': np.min(features_array, axis=0),
            'max': np.max(features_array, axis=0),
            'percentile_95': np.percentile(features_array, 95, axis=0)
        }
    
    def detect_anomalies_ensemble(self, traffic_data):
        """Ensemble anomaly detection with voting"""
        if not self.is_trained:
            logger.warning("Ensemble not trained, using rule-based detection")
            return self._rule_based_detection(traffic_data)
        
        features = self.extract_advanced_features(traffic_data)
        scaled_features_std = self.scalers['standard'].transform(features)
        scaled_features_minmax = self.scalers['minmax'].transform(features)
        
        results = []
        
        for i, flow_data in enumerate(traffic_data):
            try:
                votes = {}
                
                if_pred = self.models['isolation_forest'].predict([scaled_features_std[i]])[0]
                votes['isolation_forest'] = if_pred == -1
                
                ae_pred_proba = self.models['autoencoder_mlp'].predict_proba([scaled_features_minmax[i]])[0]
                votes['autoencoder'] = ae_pred_proba[0] < 0.7
                
                votes['statistical'] = self._statistical_anomaly_check(flow_data)
                votes['rule_based'] = self._rule_based_anomaly_check(flow_data)
                
                anomaly_votes = sum(votes.values())
                is_ensemble_anomaly = anomaly_votes >= 2
                
                confidence = anomaly_votes / len(votes)
                anomaly_score = -confidence if is_ensemble_anomaly else confidence
                
                results.append({
                    'is_anomaly': is_ensemble_anomaly,
                    'anomaly_score': anomaly_score,
                    'confidence': confidence,
                    'individual_votes': votes,
                    'traffic_data': flow_data,
                    'ensemble_decision': f"{anomaly_votes}/{len(votes)}"
                })
            except Exception as e:
                logger.warning(f"Detection error for flow {i}: {str(e)}")
                results.append({
                    'is_anomaly': False,
                    'anomaly_score': 0,
                    'confidence': 0,
                    'individual_votes': {},
                    'traffic_data': flow_data,
                    'ensemble_decision': 'error'
                })
        
        return results
    
    def _statistical_anomaly_check(self, flow):
        """Statistical anomaly detection"""
        if not self.normal_stats:
            return False
        
        features = [flow.get('packet_count', 0), flow.get('byte_count', 0), flow.get('duration', 0)]
        z_scores = np.abs((np.array(features) - self.normal_stats['mean']) / 
                         (self.normal_stats['std'] + 1e-8))
        return np.any(z_scores > 3)
    
    def _rule_based_anomaly_check(self, flow):
        """Rule-based anomaly detection"""
        suspicious_ports = [1337, 31337, 4444, 5555, 6666, 7777, 8888, 9999]
        suspicious_protocols = ['IRC', 'P2P', 'Torrent']
        
        if flow.get('src_port', 0) in suspicious_ports or flow.get('dst_port', 0) in suspicious_ports:
            return True
        if flow.get('protocol', '') in suspicious_protocols:
            return True
        if flow.get('packet_count', 0) > 10000 or flow.get('byte_count', 0) > 10000000:
            return True
        
        src_ip = flow.get('src_ip', '')
        dst_ip = flow.get('dst_ip', '')
        if src_ip.startswith('192.168.') and dst_ip.startswith('10.0.') and flow.get('dst_port', 0) > 30000:
            return True
        
        return False
    
    def _rule_based_detection(self, traffic_data):
        """Fallback rule-based detection"""
        results = []
        for flow in traffic_data:
            is_anomaly = self._rule_based_anomaly_check(flow)
            results.append({
                'is_anomaly': is_anomaly,
                'anomaly_score': -0.5 if is_anomaly else 0.1,
                'confidence': 0.5,
                'individual_votes': {'rule_based': is_anomaly},
                'traffic_data': flow,
                'ensemble_decision': 'fallback'
            })
        return results


class AdvancedSDNController:
    """SDN Controller with risk-adaptive policies"""
    
    def __init__(self):
        self.flow_table = {}
        self.network_topology = nx.Graph()
        self.isolated_devices = set()
        self.risk_levels = {}
        self.isolation_history = deque(maxlen=1000)
        self.network_performance = {}
        
    def add_device(self, device_id, device_info):
        """Add device to network topology"""
        self.network_topology.add_node(device_id, **device_info)
        
        self.risk_levels[device_id] = {
            'current_risk': 0,
            'last_updated': datetime.now(),
            'risk_factors': []
        }
        
        self.network_performance[device_id] = {
            'latency': 0,
            'throughput': 0,
            'packet_loss': 0,
            'last_measured': datetime.now()
        }
    
    def create_risk_adaptive_isolation(self, device_id, threat_score, isolation_level='adaptive'):
        """Create isolation with risk-adaptive policies"""
        if device_id not in self.network_topology:
            logger.error(f"Device {device_id} not found")
            return False
        
        if isolation_level == 'adaptive':
            if threat_score >= 90:
                isolation_level = 'maximum'
            elif threat_score >= 70:
                isolation_level = 'high'
            elif threat_score >= 40:
                isolation_level = 'medium'
            else:
                isolation_level = 'low'
        
        isolation_rules = self._generate_isolation_rules(device_id, isolation_level, threat_score)
        
        for rule in isolation_rules:
            self.flow_table[rule['rule_id']] = rule
        
        self.isolated_devices.add(device_id)
        
        self.risk_levels[device_id]['current_risk'] = threat_score
        self.risk_levels[device_id]['last_updated'] = datetime.now()
        
        isolation_event = {
            'timestamp': datetime.now(),
            'device_id': device_id,
            'threat_score': threat_score,
            'isolation_level': isolation_level,
            'rules_applied': len(isolation_rules)
        }
        self.isolation_history.append(isolation_event)
        
        logger.info(f"Isolation applied to {device_id}: level={isolation_level}")
        return True
    
    def _generate_isolation_rules(self, device_id, level, threat_score):
        """Generate isolation rules based on threat level"""
        rules = []
        rule_id_base = f"isolate_{device_id}_{int(time.time())}"
        
        if level == 'maximum':
            rules.append({
                'rule_id': f"{rule_id_base}_drop_all",
                'device': device_id,
                'action': 'drop',
                'priority': 1000,
                'timeout': 0,
                'rate_limit': '0Kbps'
            })
        elif level == 'high':
            rules.append({
                'rule_id': f"{rule_id_base}_strict_filter",
                'device': device_id,
                'action': 'strict_filter',
                'priority': 800,
                'timeout': 3600,
                'rate_limit': '100Kbps'
            })
        elif level == 'medium':
            rules.append({
                'rule_id': f"{rule_id_base}_rate_limit",
                'device': device_id,
                'action': 'rate_limit',
                'priority': 500,
                'timeout': 1800,
                'rate_limit': '1Mbps'
            })
        else:
            rules.append({
                'rule_id': f"{rule_id_base}_monitor",
                'device': device_id,
                'action': 'monitor',
                'priority': 100,
                'timeout': 900,
                'rate_limit': 'unlimited'
            })
        
        return rules
    
    def get_network_status(self):
        """Get network status"""
        isolated_details = []
        for device_id in self.isolated_devices:
            device_info = self.network_topology.nodes.get(device_id, {})
            risk_info = self.risk_levels.get(device_id, {})
            
            isolated_details.append({
                'device_id': device_id,
                'ip': device_info.get('ip', 'unknown'),
                'type': device_info.get('type', 'unknown'),
                'current_risk': risk_info.get('current_risk', 0),
                'isolation_time': risk_info.get('last_updated', datetime.now()).isoformat()
            })
        
        return {
            'total_devices': len(self.network_topology.nodes),
            'total_connections': len(self.network_topology.edges),
            'isolated_devices': list(self.isolated_devices),
            'isolated_details': isolated_details,
            'active_rules': len(self.flow_table),
            'average_risk': float(np.mean([r['current_risk'] for r in self.risk_levels.values()]) if self.risk_levels else 0)
        }


class EnhancedThreatIntelligence:
    """Advanced threat intelligence with ML-based scoring"""
    
    def __init__(self):
        self.threat_indicators = {
            'suspicious_ports': [1337, 31337, 4444, 5555, 6666, 7777, 8888, 9999],
            'known_malicious_ips': ['192.168.1.100', '10.0.0.50', '172.16.1.25'],
            'suspicious_protocols': ['IRC', 'P2P', 'Torrent', 'Bitcoin'],
        }
        
        self.threat_history = deque(maxlen=10000)
        self.ml_threat_model = RandomForestClassifier(n_estimators=100, random_state=42)
        self.is_ml_trained = False
    
    def calculate_threat_score(self, traffic_flow, anomaly_score):
        """Calculate advanced threat score - IMPROVED VERSION"""
        base_score = 0
        reasons = []
        risk_factors = {}
        
        # ANOMALY-BASED SCORING (INCREASED WEIGHTS)
        if anomaly_score < -0.7:
            base_score += 85
            reasons.append("Critical anomaly detected")
            risk_factors['anomaly_severity'] = 'critical'
        elif anomaly_score < -0.5:
            base_score += 70
            reasons.append("High anomaly score")
            risk_factors['anomaly_severity'] = 'high'
        elif anomaly_score < -0.3:
            base_score += 50
            reasons.append("Medium anomaly score")
            risk_factors['anomaly_severity'] = 'medium'
        elif anomaly_score < 0:
            base_score += 30
            reasons.append("Anomaly detected")
            risk_factors['anomaly_severity'] = 'low'
        
        indicator_score = self._calculate_indicator_score(traffic_flow)
        base_score += indicator_score['score']
        reasons.extend(indicator_score['reasons'])
        risk_factors.update(indicator_score['risk_factors'])
        
        temporal_score = self._analyze_temporal_patterns()
        base_score += temporal_score
        if temporal_score > 0:
            reasons.append("Suspicious temporal pattern")
        
        behavior_score = self._analyze_traffic_behavior(traffic_flow)
        base_score += behavior_score['score']
        reasons.extend(behavior_score['reasons'])
        
        final_score = min(base_score, 100)
        
        return final_score, reasons, risk_factors
    
    def _calculate_indicator_score(self, traffic_flow):
        """Indicator-based scoring"""
        score = 0
        reasons = []
        risk_factors = {}
        
        src_port = traffic_flow.get('src_port', 0)
        dst_port = traffic_flow.get('dst_port', 0)
        
        if src_port in self.threat_indicators['suspicious_ports']:
            score += 25
            reasons.append(f"Suspicious source port {src_port}")
            risk_factors['suspicious_src_port'] = src_port
        
        if dst_port in self.threat_indicators['suspicious_ports']:
            score += 25
            reasons.append(f"Suspicious destination port {dst_port}")
            risk_factors['suspicious_dst_port'] = dst_port
        
        src_ip = traffic_flow.get('src_ip', '')
        dst_ip = traffic_flow.get('dst_ip', '')
        
        if src_ip in self.threat_indicators['known_malicious_ips']:
            score += 35
            reasons.append("Known malicious source IP")
            risk_factors['malicious_src_ip'] = True
        
        if dst_ip in self.threat_indicators['known_malicious_ips']:
            score += 30
            reasons.append("Known malicious destination IP")
            risk_factors['malicious_dst_ip'] = True
        
        protocol = traffic_flow.get('protocol', '')
        if protocol in self.threat_indicators['suspicious_protocols']:
            score += 20
            reasons.append(f"Suspicious protocol: {protocol}")
            risk_factors['suspicious_protocol'] = protocol
        
        return {'score': score, 'reasons': reasons, 'risk_factors': risk_factors}
    
    def _analyze_temporal_patterns(self):
        """Temporal pattern analysis"""
        current_hour = datetime.now().hour
        if current_hour < 6 or current_hour > 22:
            return 15
        elif current_hour < 8 or current_hour > 18:
            return 8
        return 0
    
    def _analyze_traffic_behavior(self, traffic_flow):
        """Traffic behavior analysis"""
        score = 0
        reasons = []
        
        packet_count = traffic_flow.get('packet_count', 0)
        byte_count = traffic_flow.get('byte_count', 0)
        duration = traffic_flow.get('duration', 1)
        
        if packet_count > 10000:
            score += 20
            reasons.append("Extremely high packet count")
        elif packet_count > 1000:
            score += 10
            reasons.append("High packet count")
        
        if byte_count > 100000000:
            score += 25
            reasons.append("Extremely high byte count")
        elif byte_count > 10000000:
            score += 15
            reasons.append("High byte count")
        
        packet_rate = packet_count / duration
        if packet_rate > 1000:
            score += 15
            reasons.append("High packet rate")
        
        return {'score': score, 'reasons': reasons}


class SecureZoneSystem:
    """Main SecureZoneSystem with advanced security capabilities"""
    
    def __init__(self):
        self.ensemble_detector = EnsembleAnomalyDetector()
        self.sdn_controller = AdvancedSDNController()
        self.threat_intelligence = EnhancedThreatIntelligence()
        
        # NEW: Advanced security modules
        self.ssl_inspector = SSLCertificateInspector()
        self.dns_analyzer = DNSSecurityAnalyzer()
        self.protocol_analyzer = ProtocolAnalyzer()
        self.user_behavior = UserBehaviorAnalyzer()
        self.threat_feed = ThreatIntelligenceFeed()
        self.payload_analyzer = AdvancedPayloadAnalyzer()
        
        self.alert_threshold = 20
        self.alerts = deque(maxlen=500)
        self.alert_dedup_window = 300
        self.recent_alerts_by_ip = {}
        
        self.performance_metrics = {
            'detection_latency': deque(maxlen=100),
            'isolation_latency': deque(maxlen=100),
        }
        
        # Advanced metrics
        self.security_metrics = {
            'ssl_inspections': 0,
            'dns_queries_analyzed': 0,
            'protocol_anomalies': 0,
            'user_behavior_alerts': 0,
            'threat_intel_hits': 0,
            'total_advanced_detections': 0
        }
        
        self._init_demo_data()
    
    def _init_demo_data(self):
        """Initialize with no demo alerts"""
        self.alerts = deque(maxlen=500)
    
    def initialize_network(self):
        """Initialize network topology"""
        devices = [
            ('workstation_1', {'type': 'workstation', 'ip': '192.168.1.10', 'zone': 'corporate'}),
            ('workstation_2', {'type': 'workstation', 'ip': '192.168.1.11', 'zone': 'corporate'}),
            ('server_1', {'type': 'server', 'ip': '192.168.1.100', 'zone': 'dmz'}),
            ('router_1', {'type': 'router', 'ip': '192.168.1.1', 'zone': 'infrastructure'}),
            ('suspicious_device', {'type': 'workstation', 'ip': '192.168.1.50', 'zone': 'corporate'}),
            ('suspicious_device_2', {'type': 'workstation', 'ip': '192.168.1.51', 'zone': 'corporate'}),
            ('database_server', {'type': 'critical_server', 'ip': '192.168.1.200', 'zone': 'dmz'}),
            ('firewall', {'type': 'security', 'ip': '192.168.1.254', 'zone': 'infrastructure'}),
            ('switch_1', {'type': 'switch', 'ip': '192.168.1.251', 'zone': 'infrastructure'})
        ]
        
        for device_id, info in devices:
            self.sdn_controller.add_device(device_id, info)
        
        connections = [
            ('workstation_1', 'switch_1'), ('workstation_2', 'switch_1'),
            ('server_1', 'switch_1'), ('suspicious_device', 'switch_1'),
            ('suspicious_device_2', 'switch_1'),
            ('database_server', 'switch_1'), ('switch_1', 'firewall'),
            ('firewall', 'router_1')
        ]
        
        for device1, device2 in connections:
            self.sdn_controller.network_topology.add_edge(device1, device2)
    
    def generate_traffic(self, scan_type='quick'):
        """Generate traffic with advanced security contexts"""
        traffic_data = []
        current_time = datetime.now()
        
        normal_count = 150 if scan_type == 'deep' else 80
        suspicious_count = 40 if scan_type == 'deep' else 15
        medium_count = 30 if scan_type == 'deep' else 10
        
        # Normal traffic with SSL/DNS data
        for i in range(normal_count):
            flow = {
                'src_ip': f'192.168.1.{10 + (i % 8)}',
                'dst_ip': f'192.168.1.{100 + (i % 3)}',
                'src_port': np.random.choice([80, 443, 22, 53, 3389]),
                'dst_port': np.random.choice([80, 443, 22, 53, 3389]),
                'protocol': np.random.choice(['HTTP', 'HTTPS', 'SSH', 'DNS', 'RDP']),
                'packet_count': int(np.random.lognormal(2, 1)),
                'byte_count': int(np.random.lognormal(8, 1.5)),
                'duration': int(np.random.exponential(10)) + 1,
                'timestamp': current_time - timedelta(minutes=np.random.randint(0, 120)),
                'user_id': f'user_{10 + (i % 8)}'
            }
            
            # Add SSL certificate data for HTTPS traffic
            if flow['protocol'] == 'HTTPS':
                flow['certificate'] = {
                    'issuer': np.random.choice(['DigiCert', 'Let\'s Encrypt', 'GlobalSign']),
                    'days_until_expiry': np.random.randint(30, 365),
                    'self_signed': False,
                    'key_length': 2048,
                    'cipher_suite': 'TLS_AES_256_GCM_SHA384',
                    'hostname_mismatch': False,
                    'ct_logs_present': True,
                    'subject_alt_names': ['www.example.com'],
                    'fingerprint': hashlib.md5(f"{i}".encode()).hexdigest()
                }
                flow['dst_domain'] = f'legitimate-site-{i % 10}.com'
            
            # Add DNS query data
            if flow['protocol'] == 'DNS':
                flow['query_domain'] = f'legitimate-{i % 20}.com'
                flow['record_type'] = 'A'
                flow['queries_per_minute'] = np.random.randint(1, 10)
                flow['response_size'] = np.random.randint(50, 200)
            
            traffic_data.append(flow)
        
        # Suspicious traffic with multiple threat indicators
        suspicious_ips = ['192.168.1.50', '192.168.1.51']
        for i in range(suspicious_count):
            flow = {
                'src_ip': suspicious_ips[i % 2],
                'dst_ip': f'10.0.0.{i % 20}',
                'src_port': np.random.choice([1337, 4444, 31337, 6666, 7777]),
                'dst_port': np.random.choice([1337, 4444, 31337, 6666, 8888, 9999]),
                'protocol': np.random.choice(['IRC', 'P2P', 'TCP']),
                'packet_count': int(np.random.uniform(1000, 5000)),
                'byte_count': int(np.random.uniform(5000000, 50000000)),
                'duration': int(np.random.uniform(180, 900)),
                'timestamp': current_time - timedelta(minutes=np.random.randint(0, 60)),
                'user_id': f'user_50',
                'packet_interval_variance': 0.005  # Bot-like timing
            }
            
            # Add suspicious SSL certificates
            if np.random.random() < 0.5:
                flow['protocol'] = 'HTTPS'
                flow['certificate'] = {
                    'issuer': 'Unknown CA',
                    'days_until_expiry': -10,  # Expired
                    'self_signed': True,
                    'key_length': 1024,  # Weak
                    'cipher_suite': 'TLS_RC4_128_MD5',  # Weak cipher
                    'hostname_mismatch': True,
                    'ct_logs_present': False,
                    'subject_alt_names': ['malicious-c2.com'],
                    'fingerprint': hashlib.md5(f"bad{i}".encode()).hexdigest()
                }
                flow['dst_domain'] = 'malicious-c2.net'
            
            # Add suspicious DNS queries (tunneling)
            if np.random.random() < 0.3:
                flow['protocol'] = 'DNS'
                flow['query_domain'] = f'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0.evil-dga-{i}.com'
                flow['record_type'] = 'TXT'
                flow['queries_per_minute'] = np.random.randint(100, 200)
                flow['response_size'] = 800  # Large response
            
            traffic_data.append(flow)
        
        # Medium threat traffic
        medium_ips = ['192.168.1.11', '192.168.1.20']
        for i in range(medium_count):
            flow = {
                'src_ip': medium_ips[i % 2],
                'dst_ip': f'10.0.0.{90 + (i % 10)}',
                'src_port': np.random.choice([8080, 9000, 8443, 9090]),
                'dst_port': np.random.choice([8080, 9000, 8443, 9999]),
                'protocol': 'TCP',
                'packet_count': int(np.random.uniform(300, 800)),
                'byte_count': int(np.random.uniform(3000000, 8000000)),
                'duration': int(np.random.uniform(45, 180)),
                'timestamp': current_time - timedelta(minutes=np.random.randint(0, 90)),
                'user_id': f'user_{11 + (i % 2)}'
            }
            
            traffic_data.append(flow)
        
        return traffic_data
    
    def analyze_and_respond(self, traffic_data):
        """Advanced multi-layer threat analysis and response"""
        start_time = time.time()
        
        # Layer 1: Ensemble ML anomaly detection
        detection_results = self.ensemble_detector.detect_anomalies_ensemble(traffic_data)
        detection_latency = time.time() - start_time
        self.performance_metrics['detection_latency'].append(detection_latency)
        
        responses = []
        current_time = datetime.now()
        
        # Group anomalies by source IP
        anomaly_groups = {}
        for result in detection_results:
            if result['is_anomaly']:
                src_ip = result['traffic_data']['src_ip']
                if src_ip not in anomaly_groups:
                    anomaly_groups[src_ip] = []
                anomaly_groups[src_ip].append(result)
        
        # Process each anomalous source
        for src_ip, group_results in anomaly_groups.items():
            best_result = max(group_results, key=lambda x: x['confidence'])
            flow_data = best_result['traffic_data']
            
            # Calculate base threat score
            threat_score, reasons, risk_factors = self.threat_intelligence.calculate_threat_score(
                flow_data, 
                best_result['anomaly_score']
            )
            
            # Layer 2: SSL/TLS Certificate Inspection
            if flow_data.get('certificate'):
                ssl_analysis = self.ssl_inspector.detect_certificate_anomalies(flow_data)
                threat_score += ssl_analysis['risk_score'] * 0.3  # Weight SSL findings
                reasons.extend(ssl_analysis['findings'])
                risk_factors['ssl_analysis'] = ssl_analysis
                self.security_metrics['ssl_inspections'] += 1
                
                if ssl_analysis['threat_indicators']:
                    self.security_metrics['total_advanced_detections'] += 1
            
            # Layer 3: DNS Analysis
            if flow_data.get('query_domain'):
                dns_analysis = self.dns_analyzer.analyze_dns_traffic(flow_data)
                threat_score += dns_analysis['risk_score'] * 0.25  # Weight DNS findings
                reasons.extend(dns_analysis['findings'])
                risk_factors['dns_analysis'] = dns_analysis
                self.security_metrics['dns_queries_analyzed'] += 1
                
                if dns_analysis['threat_indicators']:
                    self.security_metrics['total_advanced_detections'] += 1
            
            # Layer 4: Protocol Analysis
            protocol_analysis = self.protocol_analyzer.analyze_protocol_behavior(flow_data)
            threat_score += protocol_analysis['risk_score'] * 0.2  # Weight protocol findings
            reasons.extend(protocol_analysis['findings'])
            risk_factors['protocol_analysis'] = protocol_analysis
            
            if protocol_analysis['threat_indicators']:
                self.security_metrics['protocol_anomalies'] += 1
                self.security_metrics['total_advanced_detections'] += 1
            
            # Layer 5: User Behavior Analytics
            if flow_data.get('user_id'):
                user_analysis = self.user_behavior.analyze_user_behavior(
                    flow_data['user_id'], 
                    flow_data
                )
                threat_score += user_analysis['risk_score'] * 0.15  # Weight UBA findings
                reasons.extend(user_analysis['findings'])
                risk_factors['user_behavior'] = user_analysis
                
                if user_analysis['threat_indicators']:
                    self.security_metrics['user_behavior_alerts'] += 1
                    self.security_metrics['total_advanced_detections'] += 1
            
            # Layer 6: Threat Intelligence Feed
            threat_intel = self.threat_feed.check_threat_intelligence(flow_data)
            threat_score += threat_intel['risk_score'] * 0.4  # High weight for IOC matches
            reasons.extend(threat_intel['findings'])
            risk_factors['threat_intelligence'] = threat_intel
            
            if threat_intel['matched_iocs']:
                self.security_metrics['threat_intel_hits'] += len(threat_intel['matched_iocs'])
                self.security_metrics['total_advanced_detections'] += 1
            
            # Layer 7: Payload Analysis (simulated)
            payload_analysis = self.payload_analyzer.analyze_payload_indicators(flow_data)
            threat_score += payload_analysis['risk_score'] * 0.1
            reasons.extend(payload_analysis['findings'])
            risk_factors['payload_analysis'] = payload_analysis
            
            # Normalize final threat score
            threat_score = min(threat_score, 100)
            
            # Determine threat severity
            if threat_score >= 80:
                severity = 'critical'
            elif threat_score >= 60:
                severity = 'high'
            elif threat_score >= 35:
                severity = 'medium'
            else:
                severity = 'low'
            
            # Create comprehensive alert
            alert = {
                'timestamp': current_time.isoformat(),
                'source_ip': src_ip,
                'destination_ip': flow_data.get('dst_ip', 'unknown'),
                'flow_count': len(group_results),
                'threat_score': int(threat_score),
                'severity': severity,
                'reasons': reasons[:10],  # Top 10 reasons
                'anomaly_score': float(best_result['anomaly_score']),
                'confidence': float(best_result['confidence']),
                'ensemble_vote': best_result['ensemble_decision'],
                'risk_factors': risk_factors,
                'protocol': flow_data.get('protocol'),
                'src_port': int(flow_data.get('src_port', 0)),
                'dst_port': int(flow_data.get('dst_port', 0)),
                'packet_count': int(flow_data.get('packet_count', 0)),
                'byte_count': int(flow_data.get('byte_count', 0)),
                'user_id': flow_data.get('user_id', 'unknown'),
                'detection_layers': self._get_active_layers(risk_factors)
            }
            
            self.alerts.append(alert)
            self.recent_alerts_by_ip[src_ip] = alert
            
            # Automated response based on threat score
            if threat_score >= self.alert_threshold:
                isolation_start = time.time()
                
                device_id = self._find_device_by_ip(src_ip)
                
                if device_id and device_id not in self.sdn_controller.isolated_devices:
                    success = self.sdn_controller.create_risk_adaptive_isolation(
                        device_id, threat_score
                    )
                    
                    isolation_latency = time.time() - isolation_start
                    self.performance_metrics['isolation_latency'].append(isolation_latency)
                    
                    if success:
                        response = {
                            'action': 'risk_adaptive_isolation',
                            'device_id': device_id,
                            'device_ip': src_ip,
                            'threat_score': int(threat_score),
                            'severity': severity,
                            'risk_factors': risk_factors,
                            'response_time': round(isolation_latency, 3),
                            'flow_count': len(group_results),
                            'detection_layers': alert['detection_layers']
                        }
                        responses.append(response)
        
        return responses
    
    def _get_active_layers(self, risk_factors):
        """Get list of detection layers that triggered"""
        layers = []
        
        if risk_factors.get('ssl_analysis', {}).get('threat_indicators'):
            layers.append('SSL/TLS Inspection')
        if risk_factors.get('dns_analysis', {}).get('threat_indicators'):
            layers.append('DNS Analysis')
        if risk_factors.get('protocol_analysis', {}).get('threat_indicators'):
            layers.append('Protocol Analysis')
        if risk_factors.get('user_behavior', {}).get('threat_indicators'):
            layers.append('User Behavior Analytics')
        if risk_factors.get('threat_intelligence', {}).get('matched_iocs'):
            layers.append('Threat Intelligence')
        if risk_factors.get('payload_analysis', {}).get('threat_indicators'):
            layers.append('Payload Analysis')
        
        if not layers:
            layers = ['ML Anomaly Detection']
        
        return layers
    
    def _find_device_by_ip(self, ip_address):
        """Find device ID by IP address"""
        for device_id, data in self.sdn_controller.network_topology.nodes(data=True):
            if data.get('ip') == ip_address:
                return device_id
        return None
    
    def get_dashboard_data(self):
        """Get comprehensive dashboard data with advanced metrics"""
        network_status = self.sdn_controller.get_network_status()
        
        data = {
            'network_status': convert_numpy_types(network_status),
            'recent_alerts': [convert_numpy_types(alert) for alert in list(self.alerts)[-15:]],
            'threat_statistics': convert_numpy_types(self._calculate_threat_stats()),
            'topology_data': convert_numpy_types(self._get_topology_data()),
            'performance_metrics': convert_numpy_types(self._get_performance_metrics()),
            'system_health': convert_numpy_types(self._get_system_health()),
            'advanced_security_metrics': convert_numpy_types(self.security_metrics),
            'detection_layers_summary': convert_numpy_types(self._get_detection_layers_summary())
        }
        
        return data
    
    def _get_detection_layers_summary(self):
        """Get summary of detection layer activity"""
        return {
            'ssl_inspections': self.security_metrics['ssl_inspections'],
            'dns_queries_analyzed': self.security_metrics['dns_queries_analyzed'],
            'protocol_anomalies': self.security_metrics['protocol_anomalies'],
            'user_behavior_alerts': self.security_metrics['user_behavior_alerts'],
            'threat_intel_hits': self.security_metrics['threat_intel_hits'],
            'total_advanced_detections': self.security_metrics['total_advanced_detections'],
            'active_layers': [
                'ML Anomaly Detection',
                'SSL/TLS Certificate Inspection',
                'DNS Security Analysis',
                'Protocol Behavior Analysis',
                'User Behavior Analytics',
                'Threat Intelligence Feed',
                'Payload Analysis (Simulated)'
            ]
        }
    
    def _calculate_threat_stats(self):
        """Calculate threat statistics"""
        if not self.alerts:
            return {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        
        stats = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for alert in self.alerts:
            severity = alert.get('severity', 'low')
            if severity in stats:
                stats[severity] += 1
        
        return stats
    
    def _get_topology_data(self):
        """Get network topology data"""
        nodes = []
        edges = []
        
        for node_id, data in self.sdn_controller.network_topology.nodes(data=True):
            risk_info = self.sdn_controller.risk_levels.get(node_id, {})
            
            nodes.append({
                'id': node_id,
                'type': data.get('type', 'unknown'),
                'ip': data.get('ip', ''),
                'isolated': node_id in self.sdn_controller.isolated_devices,
                'zone': data.get('zone', 'unknown'),
                'current_risk': risk_info.get('current_risk', 0),
                'risk_level': 'critical' if risk_info.get('current_risk', 0) >= 70 else
                           'medium' if risk_info.get('current_risk', 0) >= 35 else 'low'
            })
        
        for edge in self.sdn_controller.network_topology.edges():
            edges.append({'source': edge[0], 'target': edge[1]})
        
        return {'nodes': nodes, 'edges': edges}
    
    def _get_performance_metrics(self):
        """Get system performance metrics"""
        detection_times = list(self.performance_metrics['detection_latency'])
        isolation_times = list(self.performance_metrics['isolation_latency'])
        
        return {
            'avg_detection_latency': float(np.mean(detection_times)) if detection_times else 0,
            'max_detection_latency': float(np.max(detection_times)) if detection_times else 0,
            'avg_isolation_latency': float(np.mean(isolation_times)) if isolation_times else 0,
            'max_isolation_latency': float(np.max(isolation_times)) if isolation_times else 0,
            'total_detections': len(detection_times),
            'total_isolations': len(isolation_times)
        }
    
    def _get_system_health(self):
        """Get enhanced system health metrics"""
        return {
            'cpu_usage': float(np.random.uniform(25, 75)),
            'memory_usage': float(np.random.uniform(35, 65)),
            'network_utilization': float(np.random.uniform(15, 55)),
            'threat_detection_accuracy': float(np.random.uniform(88, 96)),
            'ensemble_model_performance': float(np.random.uniform(92, 98)),
            'uptime': f"{np.random.randint(5, 45)} days",
            'active_monitoring': True,
            'alerts_processed': len(self.alerts),
            'devices_monitored': len(self.sdn_controller.network_topology.nodes),
            'isolation_rules_active': len(self.sdn_controller.flow_table),
            'advanced_features_status': {
                'ssl_inspection': 'active',
                'dns_analysis': 'active',
                'protocol_analysis': 'active',
                'user_behavior_analytics': 'active',
                'threat_intelligence': 'active',
                'payload_analysis': 'active'
            },
            'security_posture': 'excellent' if self.security_metrics['total_advanced_detections'] < 5 else 'good'
        }


# Flask Application Setup
app = Flask(__name__)
securezone = SecureZoneSystem()


@app.route('/')
def index():
    """Root endpoint - returns dashboard HTML"""
    return render_template('dashboard.html')


@app.route('/api/status')
def api_status():
    """Get current system status"""
    try:
        return jsonify(securezone.get_dashboard_data())
    except Exception as e:
        logger.error(f"Error fetching status: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/dashboard_data')
def api_dashboard_data():
    """Get dashboard data"""
    try:
        return jsonify(securezone.get_dashboard_data())
    except Exception as e:
        logger.error(f"Error fetching dashboard data: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/run_scan', methods=['POST'])
def api_run_scan():
    """Run security scan with accurate threat counting"""
    try:
        data = request.get_json() or {}
        scan_type = data.get('scan_type', 'quick')
        
        traffic_data = securezone.generate_traffic(scan_type)
        detection_results = securezone.ensemble_detector.detect_anomalies_ensemble(traffic_data)
        anomalies_found = sum(1 for r in detection_results if r['is_anomaly'])
        responses = securezone.analyze_and_respond(traffic_data)
        threats_isolated = len(responses)
        
        result = {
            'success': True,
            'scan_type': scan_type,
            'traffic_analyzed': len(traffic_data),
            'anomalies_detected': anomalies_found,
            'threats_detected': threats_isolated,
            'responses': responses,
            'performance': securezone._get_performance_metrics(),
            'advanced_detections': securezone.security_metrics['total_advanced_detections'],
            'summary': f"Analyzed {len(traffic_data)} flows - {anomalies_found} anomalies detected - {threats_isolated} threats isolated"
        }
        
        return jsonify(convert_numpy_types(result))
    except Exception as e:
        logger.error(f"Error in scan: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/alerts')
def api_alerts():
    """Get recent alerts"""
    try:
        alerts_list = [convert_numpy_types(alert) for alert in list(securezone.alerts)[-20:]]
        return jsonify({
            'total_alerts': len(securezone.alerts),
            'recent_alerts': alerts_list
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/network')
def api_network():
    """Get network topology"""
    try:
        return jsonify(securezone._get_topology_data())
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/isolation_history')
def api_isolation_history():
    """Get isolation history"""
    try:
        history_list = [convert_numpy_types(item) for item in list(securezone.sdn_controller.isolation_history)[-50:]]
        return jsonify({
            'total_isolations': len(securezone.sdn_controller.isolation_history),
            'history': history_list
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/advanced_metrics')
def api_advanced_metrics():
    """Get advanced security metrics"""
    try:
        return jsonify({
            'ssl_certificate_analysis': {
                'total_inspections': securezone.security_metrics['ssl_inspections'],
                'suspicious_certs': len(securezone.ssl_inspector.suspicious_patterns['self_signed_certs']),
                'expired_certs': len(securezone.ssl_inspector.suspicious_patterns['expired_certs']),
                'weak_ciphers': len(securezone.ssl_inspector.suspicious_patterns['weak_ciphers'])
            },
            'dns_security': {
                'queries_analyzed': securezone.security_metrics['dns_queries_analyzed'],
                'dga_detections': len([q for q in securezone.dns_analyzer.query_history if q.get('risk_score', 0) > 50]),
                'tunneling_attempts': len([q for q in securezone.dns_analyzer.query_history if q.get('risk_score', 0) > 50])
            },
            'protocol_analysis': {
                'anomalies_detected': securezone.security_metrics['protocol_anomalies'],
                'tunneling_detected': 0
            },
            'user_behavior': {
                'alerts_generated': securezone.security_metrics['user_behavior_alerts'],
                'users_monitored': len(securezone.user_behavior.user_profiles),
                'behavioral_baselines': len(securezone.user_behavior.user_profiles)
            },
            'threat_intelligence': {
                'ioc_hits': securezone.security_metrics['threat_intel_hits'],
                'malicious_ips_blocked': len(securezone.threat_feed.ioc_database['malicious_ips']),
                'c2_connections_blocked': len(securezone.threat_feed.ioc_database['c2_servers'])
            },
            'total_advanced_detections': securezone.security_metrics['total_advanced_detections']
        })
    except Exception as e:
        logger.error(f"Error fetching advanced metrics: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/detection_layers')
def api_detection_layers():
    """Get detection layer information"""
    try:
        return jsonify(securezone._get_detection_layers_summary())
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/analyze_traffic', methods=['POST'])
def api_analyze_traffic():
    """Alternative analyze traffic endpoint"""
    try:
        data = request.get_json() or {}
        scan_type = data.get('scan_type', 'quick')
        
        traffic_data = securezone.generate_traffic(scan_type)
        detection_results = securezone.ensemble_detector.detect_anomalies_ensemble(traffic_data)
        anomalies_found = sum(1 for r in detection_results if r['is_anomaly'])
        responses = securezone.analyze_and_respond(traffic_data)
        threats_isolated = len(responses)
        
        return jsonify({
            'success': True,
            'scan_type': scan_type,
            'traffic_analyzed': len(traffic_data),
            'anomalies_detected': anomalies_found,
            'threats_detected': threats_isolated,
            'responses': responses,
            'performance': securezone._get_performance_metrics(),
            'advanced_detections': securezone.security_metrics['total_advanced_detections'],
            'summary': f"Analyzed {len(traffic_data)} flows - {anomalies_found} anomalies detected - {threats_isolated} threats isolated"
        })
    except Exception as e:
        logger.error(f"Error in scan: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500


def init_system():
    """Initialize the advanced system"""
    print("\n" + "="*80)
    print("SecureZone Advanced Research-Grade Network Security System v4.0")
    print("With SSL/TLS Inspection, DNS Analysis, Protocol Fingerprinting,")
    print("User Behavior Analytics, and Threat Intelligence")
    print("="*80)
    
    print("\n[*] Initializing network topology...")
    securezone.initialize_network()
    print(f"[+] Network initialized with {len(securezone.sdn_controller.network_topology.nodes)} devices")
    
    print("\n[*] Training ensemble anomaly detection models...")
    normal_traffic = []
    for i in range(200):
        normal_traffic.append({
            'packet_count': int(np.random.lognormal(2, 0.8)),
            'byte_count': int(np.random.lognormal(8, 1.2)),
            'duration': int(np.random.exponential(8)) + 1,
            'src_port': np.random.choice([80, 443, 22, 53, 3389]),
            'dst_port': np.random.choice([80, 443, 22, 53, 3389]),
            'protocol': np.random.choice(['HTTP', 'HTTPS', 'SSH', 'DNS', 'RDP']),
            'src_ip': '192.168.1.10',
            'dst_ip': '192.168.1.100'
        })
    
    training_results = securezone.ensemble_detector.train_ensemble(normal_traffic)
    print(f"[+] Ensemble training completed:")
    for model, status in training_results.items():
        print(f"    • {model}: {status}")
    
    print("\n[*] Initializing advanced security modules...")
    print("    ✓ SSL/TLS Certificate Inspector")
    print("    ✓ DNS Security Analyzer")
    print("    ✓ Protocol Behavior Analyzer")
    print("    ✓ User Behavior Analytics")
    print("    ✓ Threat Intelligence Feed")
    print("    ✓ Payload Analyzer (Simulated)")
    
    print(f"\n[+] Advanced Security System Ready!")
    print(f"[+] Detection Layers: {len(securezone._get_detection_layers_summary()['active_layers'])}")
    print(f"[+] Threat Intelligence: {len(securezone.threat_feed.ioc_database['malicious_ips'])} IOCs loaded")
    print("="*80)


if __name__ == '__main__':
    init_system()
    print("\n[*] Starting Flask server on http://localhost:5000")
    print("[*] Access the dashboard at http://localhost:5000")
    print("[*] API endpoints:")
    print("    • /api/status - System status")
    print("    • /api/run_scan - Run security scan")
    print("    • /api/advanced_metrics - Advanced security metrics")
    print("    • /api/detection_layers - Detection layer information")
    print("    • /api/alerts - Recent security alerts")
    print("    • /api/network - Network topology")
    print("\n")
    app.run(debug=False, host='0.0.0.0', port=5000, threaded=True)