"""Feature Extraction Module for NIDS

Extracts machine learning features from network traffic packets.
Features include statistical, behavioral, and protocol-specific attributes.
"""

from typing import Dict, List, Any, Optional
from collections import defaultdict
import statistics
from datetime import datetime, timedelta

from .logger import ThreatLogger


class FeatureExtractor:
    """Extracts ML features from network packets and flows."""
    
    # Feature thresholds for anomaly detection
    SYN_THRESHOLD = 100  # Suspicious if > 100 SYNs from same IP
    PORT_SCAN_THRESHOLD = 50  # Ports accessed > 50 from same IP
    PACKET_RATE_THRESHOLD = 1000  # Packets per minute threshold
    DATA_RATE_THRESHOLD = 1000000  # Bytes per minute threshold
    
    def __init__(self, flow_timeout: int = 300):
        """
        Initialize feature extractor.
        
        Args:
            flow_timeout: Seconds before considering flow inactive
        """
        self.logger = ThreatLogger()
        self.flow_timeout = flow_timeout
        self.flows: Dict[str, Dict[str, Any]] = {}
        self.global_stats = defaultdict(int)
    
    def _get_flow_key(self, src_ip: str, dst_ip: str, protocol: str) -> str:
        """Get unique flow identifier.
        
        Args:
            src_ip: Source IP address
            dst_ip: Destination IP address
            protocol: Protocol (TCP/UDP/ICMP)
            
        Returns:
            Flow key string
        """
        return f"{src_ip}:{dst_ip}:{protocol}"
    
    def extract_packet_features(self, packet_data: Dict[str, Any]) -> Dict[str, float]:
        """Extract individual packet features.
        
        Args:
            packet_data: Parsed packet dictionary from PacketProcessor
            
        Returns:
            Dictionary of extracted features
        """
        features = {
            'payload_size': float(packet_data.get('payload_size', 0)),
            'port_number': float(packet_data.get('dst_port', 0)) if packet_data.get('dst_port') else 0.0,
            'protocol_type': self._encode_protocol(packet_data.get('protocol')),
            'flag_count': float(len(packet_data.get('flags', []))),
        }
        
        # Flag-specific features (SYN, FIN, RST, ACK)
        flags = packet_data.get('flags', [])
        features['has_syn'] = 1.0 if 'SYN' in flags else 0.0
        features['has_fin'] = 1.0 if 'FIN' in flags else 0.0
        features['has_rst'] = 1.0 if 'RST' in flags else 0.0
        features['has_ack'] = 1.0 if 'ACK' in flags else 0.0
        
        return features
    
    def _encode_protocol(self, protocol: Optional[str]) -> float:
        """Encode protocol as number.
        
        Args:
            protocol: Protocol string (TCP/UDP/ICMP)
            
        Returns:
            Encoded protocol value
        """
        protocol_map = {'TCP': 1.0, 'UDP': 2.0, 'ICMP': 3.0}
        return protocol_map.get(protocol, 0.0)
    
    def _decode_protocol(self, code: float) -> str:
        """Decode protocol from number.
        
        Args:
            code: Encoded protocol value
            
        Returns:
            Protocol string
        """
        decode_map = {1.0: 'TCP', 2.0: 'UDP', 3.0: 'ICMP'}
        return decode_map.get(code, 'Unknown')
    
    def extract_flow_features(self, packet_data: Dict[str, Any]) -> Dict[str, float]:
        """Extract flow-based statistical features.
        
        Args:
            packet_data: Parsed packet from PacketProcessor
            
        Returns:
            Dictionary of flow-based features
        """
        src_ip = packet_data.get('src_ip')
        dst_ip = packet_data.get('dst_ip')
        protocol = packet_data.get('protocol')
        
        if not (src_ip and dst_ip and protocol):
            return {}
        
        flow_key = self._get_flow_key(src_ip, dst_ip, protocol)
        
        # Initialize or update flow
        if flow_key not in self.flows:
            self.flows[flow_key] = {
                'packets': [],
                'created_at': datetime.now(),
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'protocol': protocol,
                'ports_accessed': set(),
                'syn_count': 0,
                'fin_count': 0,
                'rst_count': 0,
                'total_bytes': 0,
            }
        
        flow = self.flows[flow_key]
        flow['packets'].append(packet_data)
        flow['total_bytes'] += packet_data.get('payload_size', 0)
        
        if 'SYN' in packet_data.get('flags', []):
            flow['syn_count'] += 1
        if 'FIN' in packet_data.get('flags', []):
            flow['fin_count'] += 1
        if 'RST' in packet_data.get('flags', []):
            flow['rst_count'] += 1
        
        if packet_data.get('dst_port'):
            flow['ports_accessed'].add(packet_data['dst_port'])
        
        # Cleanup old flows
        self._cleanup_old_flows()
        
        # Extract features from current flow state
        return self._get_flow_statistics(flow_key, flow)
    
    def _cleanup_old_flows(self) -> None:
        """Remove inactive flows."""
        current_time = datetime.now()
        expired_flows = [
            key for key, flow in self.flows.items()
            if (current_time - flow['created_at']).seconds > self.flow_timeout
        ]
        for flow_key in expired_flows:
            del self.flows[flow_key]
    
    def _get_flow_statistics(self, flow_key: str, flow: Dict[str, Any]) -> Dict[str, float]:
        """Calculate statistics for a flow.
        
        Args:
            flow_key: Flow identifier
            flow: Flow data dictionary
            
        Returns:
            Dictionary of flow statistics
        """
        packet_count = len(flow['packets'])
        payload_sizes = [p.get('payload_size', 0) for p in flow['packets']]
        
        stats = {
            'packet_count': float(packet_count),
            'total_bytes': float(flow['total_bytes']),
            'avg_payload_size': float(statistics.mean(payload_sizes)) if payload_sizes else 0.0,
            'unique_ports': float(len(flow['ports_accessed'])),
            'syn_count': float(flow['syn_count']),
            'fin_count': float(flow['fin_count']),
            'rst_count': float(flow['rst_count']),
            'syn_fin_ratio': float(flow['syn_count'] / (flow['fin_count'] + 1)),
            'syn_rst_ratio': float(flow['syn_count'] / (flow['rst_count'] + 1)),
        }
        
        return stats
    
    def detect_anomalies(self, flow_key: str) -> List[str]:
        """Detect potential anomalies in a flow.
        
        Args:
            flow_key: Flow identifier
            
        Returns:
            List of detected anomaly types
        """
        anomalies = []
        
        if flow_key not in self.flows:
            return anomalies
        
        flow = self.flows[flow_key]
        
        # Detect potential SYN flood
        if flow['syn_count'] > self.SYN_THRESHOLD:
            anomalies.append('syn_flood')
        
        # Detect potential port scan
        if len(flow['ports_accessed']) > self.PORT_SCAN_THRESHOLD:
            anomalies.append('port_scan')
        
        # Detect potential DDoS pattern (high packet rate)
        if len(flow['packets']) > self.PACKET_RATE_THRESHOLD / 60:  # packets per second
            anomalies.append('high_packet_rate')
        
        # Detect unusual flag combinations
        if flow['syn_count'] > 0 and flow['fin_count'] > (flow['syn_count'] * 0.5):
            anomalies.append('unusual_flag_combo')
        
        return anomalies
    
    def get_all_flows(self) -> Dict[str, Dict[str, Any]]:
        """Get all active flows.
        
        Returns:
            Dictionary of all active flows
        """
        return self.flows.copy()
    
    def clear_flows(self) -> None:
        """Clear all flow data."""
        self.flows.clear()
        self.logger.log_threat('info', 'Cleared all flows')
