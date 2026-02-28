import random
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional
import threading
import queue

class NetworkMonitor:
    """Live network monitoring with threat detection"""
    
    # Suspicious IP patterns
    BLOCKED_IPS = [
        "192.168.1.100", "10.0.0.99", "172.16.0.50",  # Known malicious
        "45.142.212.0", "185.220.101.0", "91.219.236.0"  # Suspicious ranges
    ]
    
    SUSPICIOUS_PORTS = [22, 23, 135, 139, 445, 3389, 4444, 5555, 6666, 31337]
    
    # Common attack signatures
    ATTACK_PATTERNS = {
        'port_scan': ['SYN scan', 'UDP scan', 'TCP connect scan'],
        'brute_force': ['SSH brute force', 'RDP brute force', 'FTP brute force'],
        'malware_c2': ['Command & Control', 'Beaconing', 'Data exfiltration'],
        'ddos': ['SYN flood', 'UDP flood', 'HTTP flood'],
        'exploit': ['Buffer overflow', 'SQL injection attempt', 'XSS attempt']
    }
    
    def __init__(self, db_storage_callback=None):
        self.traffic_queue = queue.Queue()
        self.network_logs = []
        self.is_monitoring = False
        self.monitor_thread = None
        self.packet_counter = 0
        self.db_storage_callback = db_storage_callback  # Callback to store in database
        
    def start_monitoring(self):
        """Start the network monitoring thread"""
        if not self.is_monitoring:
            self.is_monitoring = True
            self.monitor_thread = threading.Thread(target=self._generate_traffic)
            self.monitor_thread.daemon = True
            self.monitor_thread.start()
    
    def stop_monitoring(self):
        """Stop the network monitoring"""
        self.is_monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=2)
    
    def _generate_traffic(self):
        """Generate simulated network traffic"""
        while self.is_monitoring:
            try:
                # Generate traffic every 1-3 seconds
                time.sleep(random.uniform(1, 3))
                
                # Generate a network packet
                packet = self._create_simulated_packet()
                
                # Analyze for threats
                threat_result = self._analyze_packet(packet)
                
                # Log the packet
                log_entry = {
                    'timestamp': datetime.now(),
                    'source_ip': packet['source_ip'],
                    'dest_ip': packet['dest_ip'],
                    'source_port': packet['source_port'],
                    'dest_port': packet['dest_port'],
                    'protocol': packet['protocol'],
                    'packet_size': packet['size'],
                    'threat_detected': threat_result['is_threat'],
                    'threat_type': threat_result['threat_type'],
                    'risk_score': threat_result['risk_score'],
                    'severity': threat_result['severity'],
                    'details': threat_result['details']
                }
                
                self.network_logs.append(log_entry)
                
                # Store in database if callback provided (only for threats)
                if self.db_storage_callback and threat_result['is_threat']:
                    try:
                        self.db_storage_callback(log_entry)
                    except Exception as e:
                        print(f"Database storage error: {e}")
                
                # Keep only last 1000 logs
                if len(self.network_logs) > 1000:
                    self.network_logs = self.network_logs[-1000:]
                
                self.packet_counter += 1
                
            except Exception as e:
                print(f"Network monitoring error: {e}")
                time.sleep(1)
    
    def _create_simulated_packet(self) -> Dict:
        """Create a simulated network packet"""
        
        # Random source and destination IPs
        source_octets = [random.randint(1, 255) for _ in range(4)]
        dest_octets = [random.randint(1, 255) for _ in range(4)]
        
        source_ip = '.'.join(map(str, source_octets))
        dest_ip = '.'.join(map(str, dest_octets))
        
        # Occasionally use suspicious IPs (10% chance)
        if random.random() < 0.1:
            source_ip = random.choice(self.BLOCKED_IPS)
        
        # Protocol selection
        protocols = ['TCP', 'UDP', 'ICMP', 'HTTP', 'HTTPS', 'DNS', 'SSH', 'FTP']
        protocol = random.choice(protocols)
        
        # Port selection based on protocol
        if protocol == 'HTTP':
            dest_port = 80
        elif protocol == 'HTTPS':
            dest_port = 443
        elif protocol == 'SSH':
            dest_port = 22
        elif protocol == 'FTP':
            dest_port = 21
        elif protocol == 'DNS':
            dest_port = 53
        else:
            # Random port, occasionally suspicious
            if random.random() < 0.15:
                dest_port = random.choice(self.SUSPICIOUS_PORTS)
            else:
                dest_port = random.randint(1024, 65535)
        
        # Random source port
        source_port = random.randint(1024, 65535)
        
        # Packet size
        packet_size = random.randint(64, 1500)
        
        return {
            'source_ip': source_ip,
            'dest_ip': dest_ip,
            'source_port': source_port,
            'dest_port': dest_port,
            'protocol': protocol,
            'size': packet_size,
            'timestamp': datetime.now()
        }
    
    def _analyze_packet(self, packet: Dict) -> Dict:
        """Analyze a packet for threats"""
        
        risk_score = 0
        threat_indicators = []
        
        # Check for suspicious source IP
        if packet['source_ip'] in self.BLOCKED_IPS:
            risk_score += 40
            threat_indicators.append('Known malicious IP address')
        
        # Check for suspicious destination port
        if packet['dest_port'] in self.SUSPICIOUS_PORTS:
            risk_score += 25
            threat_indicators.append(f'Suspicious port access: {packet["dest_port"]}')
        
        # Protocol-based risk assessment
        if packet['protocol'] in ['SSH', 'FTP', 'Telnet']:
            risk_score += 10
            threat_indicators.append(f'Cleartext/legacy protocol: {packet["protocol"]}')
        
        # Check for unusual packet sizes
        if packet['size'] > 1400:
            risk_score += 5
            threat_indicators.append('Large packet size')
        
        # Simulate additional threat detection (15% chance of threat)
        if random.random() < 0.15:
            threat_type = random.choice([
                'Port Scan Detected',
                'Suspicious Connection',
                'Malware Beacon',
                'Data Exfiltration Attempt',
                'Brute Force Attack'
            ])
            risk_score += 30
            threat_indicators.append(threat_type)
        else:
            threat_type = 'Normal Traffic'
        
        # Determine severity
        if risk_score >= 70:
            severity = 'High'
        elif risk_score >= 40:
            severity = 'Medium'
        else:
            severity = 'Low'
        
        is_threat = risk_score >= 30
        
        return {
            'is_threat': is_threat,
            'threat_type': threat_type,
            'risk_score': min(risk_score, 100),
            'severity': severity,
            'details': {
                'indicators': threat_indicators,
                'packet_info': packet
            }
        }
    
    def get_network_stats(self) -> Dict:
        """Get current network statistics"""
        
        if not self.network_logs:
            return {
                'total_packets': 0,
                'threats_detected': 0,
                'high_risk_packets': 0,
                'medium_risk_packets': 0,
                'active_connections': 0,
                'bandwidth_usage': '0 Mbps',
                'recent_packets': [],
                'threats_by_type': {},
                'top_source_ips': [],
                'traffic_trend': []
            }
        
        # Get recent packets (last 5 minutes)
        recent_time = datetime.now() - timedelta(minutes=5)
        recent_packets = [log for log in self.network_logs if log['timestamp'] > recent_time]
        
        # Calculate statistics
        total_packets = len(recent_packets)
        threats_detected = len([p for p in recent_packets if p['threat_detected']])
        high_risk = len([p for p in recent_packets if p['severity'] == 'High'])
        medium_risk = len([p for p in recent_packets if p['severity'] == 'Medium'])
        
        # Count unique connections
        unique_ips = set()
        for packet in recent_packets:
            unique_ips.add(packet['source_ip'])
            unique_ips.add(packet['dest_ip'])
        
        # Group threats by type
        threats_by_type = {}
        for packet in recent_packets:
            if packet['threat_detected']:
                threat_type = packet['threat_type']
                threats_by_type[threat_type] = threats_by_type.get(threat_type, 0) + 1
        
        # Top source IPs
        source_ip_counts = {}
        for packet in recent_packets:
            ip = packet['source_ip']
            source_ip_counts[ip] = source_ip_counts.get(ip, 0) + 1
        
        top_source_ips = sorted(source_ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        
        # Calculate bandwidth (simulated)
        total_bytes = sum(p['packet_size'] for p in recent_packets)
        bandwidth_mbps = round((total_bytes * 8) / (5 * 60 * 1000000), 2)  # 5 minutes
        
        # Generate traffic trend (last 10 data points)
        traffic_trend = []
        for i in range(10):
            time_window = datetime.now() - timedelta(minutes=i*0.5)
            window_packets = len([p for p in recent_packets 
                                if p['timestamp'] > time_window - timedelta(minutes=0.5) 
                                and p['timestamp'] <= time_window])
            traffic_trend.append({
                'time': time_window.strftime('%H:%M'),
                'packets': window_packets,
                'threats': len([p for p in recent_packets 
                              if p['timestamp'] > time_window - timedelta(minutes=0.5) 
                              and p['timestamp'] <= time_window 
                              and p['threat_detected']])
            })
        
        traffic_trend.reverse()
        
        return {
            'total_packets': total_packets,
            'threats_detected': threats_detected,
            'high_risk_packets': high_risk,
            'medium_risk_packets': medium_risk,
            'active_connections': len(unique_ips),
            'bandwidth_usage': f'{bandwidth_mbps} Mbps',
            'recent_packets': recent_packets[-50:],  # Last 50 packets
            'threats_by_type': threats_by_type,
            'top_source_ips': top_source_ips,
            'traffic_trend': traffic_trend
        }
    
    def get_live_packet(self) -> Optional[Dict]:
        """Get the most recent packet for live monitoring"""
        if self.network_logs:
            return self.network_logs[-1]
        return None

# Global network monitor instance
network_monitor = NetworkMonitor()
