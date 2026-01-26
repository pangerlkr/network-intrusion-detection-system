"""Network Intrusion Detection System Engine

Main orchestration engine that coordinates packet processing, feature extraction,
and anomaly detection for network intrusion detection.
"""

from typing import Dict, List, Optional, Any, Callable
from datetime import datetime
import threading
import time

from .logger import ThreatLogger
from .config import Config
from .packet_processor import PacketProcessor
from .feature_extractor import FeatureExtractor


class NIDSEngine:
    """Main Network Intrusion Detection System Engine."""
    
    # Detection threshold for ML models
    ANOMALY_SCORE_THRESHOLD = 0.7
    ALERT_THRESHOLD = 0.85
    
    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize NIDS Engine.
        
        Args:
            config_path: Path to YAML configuration file
        """
        self.config = Config(config_path) if config_path else Config()
        self.logger = ThreatLogger()
        self.packet_processor = None
        self.feature_extractor = FeatureExtractor()
        
        self.is_running = False
        self.engine_thread: Optional[threading.Thread] = None
        self.detection_callbacks: List[Callable] = []
        self.stats = {
            'packets_processed': 0,
            'anomalies_detected': 0,
            'alerts_raised': 0,
            'threats_identified': [],
            'start_time': None,
            'uptime_seconds': 0,
        }
    
    def initialize(self) -> bool:
        """
        Initialize NIDS Engine with configured parameters.
        
        Returns:
            True if initialization successful, False otherwise
        """
        try:
            # Get network interface from config
            interface = self.config.get('network.interface', None)
            packet_count = self.config.get('network.packet_count', 0)
            
            # Initialize packet processor
            self.packet_processor = PacketProcessor(
                interface=interface,
                packet_count=packet_count
            )
            
            # Register callback
            self.packet_processor.set_packet_callback(self._process_packet)
            
            self.logger.log_threat(
                'info',
                'NIDS Engine initialized successfully'
            )
            return True
            
        except Exception as e:
            self.logger.log_threat(
                'error',
                f'Failed to initialize NIDS Engine: {str(e)}',
                {'error_type': type(e).__name__}
            )
            return False
    
    def _process_packet(self, packet_data: Dict[str, Any]) -> None:
        """Internal packet processing callback.
        
        Args:
            packet_data: Parsed packet from PacketProcessor
        """
        try:
            self.stats['packets_processed'] += 1
            
            # Extract features
            packet_features = self.feature_extractor.extract_packet_features(packet_data)
            flow_features = self.feature_extractor.extract_flow_features(packet_data)
            
            # Detect anomalies
            if flow_features:
                src_ip = packet_data.get('src_ip')
                dst_ip = packet_data.get('dst_ip')
                protocol = packet_data.get('protocol')
                
                if src_ip and dst_ip and protocol:
                    flow_key = f"{src_ip}:{dst_ip}:{protocol}"
                    anomalies = self.feature_extractor.detect_anomalies(flow_key)
                    
                    if anomalies:
                        self._handle_anomaly(packet_data, anomalies, flow_features)
            
        except Exception as e:
            self.logger.log_threat(
                'error',
                f'Error in packet processing: {str(e)}',
                {'error_type': type(e).__name__}
            )
    
    def _handle_anomaly(self, packet_data: Dict[str, Any], anomalies: List[str],
                       flow_features: Dict[str, float]) -> None:
        """Handle detected anomaly.
        
        Args:
            packet_data: Original packet data
            anomalies: List of detected anomaly types
            flow_features: Extracted flow features
        """
        # Calculate anomaly score based on detection confidence
        anomaly_score = self._calculate_anomaly_score(anomalies, flow_features)
        
        # Log anomaly
        self.stats['anomalies_detected'] += 1
        
        threat_info = {
            'timestamp': datetime.now().isoformat(),
            'src_ip': packet_data.get('src_ip'),
            'dst_ip': packet_data.get('dst_ip'),
            'protocol': packet_data.get('protocol'),
            'anomalies': anomalies,
            'anomaly_score': anomaly_score,
            'flow_features': flow_features,
        }
        
        # Trigger alert if score exceeds threshold
        if anomaly_score >= self.ALERT_THRESHOLD:
            self.stats['alerts_raised'] += 1
            self.stats['threats_identified'].append(threat_info)
            self.logger.log_threat('warning', f'Intrusion detected: {anomalies}', threat_info)
            self._trigger_detection_callbacks(threat_info)
        else:
            self.logger.log_threat('info', f'Anomaly detected: {anomalies}', threat_info)
    
    def _calculate_anomaly_score(self, anomalies: List[str],
                                flow_features: Dict[str, float]) -> float:
        """Calculate anomaly detection score.
        
        Args:
            anomalies: List of detected anomaly types
            flow_features: Flow features dictionary
            
        Returns:
            Anomaly score between 0 and 1
        """
        score = 0.0
        
        # Base scores for different anomaly types
        anomaly_scores = {
            'syn_flood': 0.9,
            'port_scan': 0.85,
            'high_packet_rate': 0.80,
            'unusual_flag_combo': 0.75,
        }
        
        # Calculate weighted score
        if anomalies:
            scores = [anomaly_scores.get(a, 0.5) for a in anomalies]
            score = sum(scores) / len(scores) if scores else 0.0
        
        # Adjust score based on flow characteristics
        if flow_features:
            syn_count = flow_features.get('syn_count', 0)
            packet_count = flow_features.get('packet_count', 0)
            
            # Increase score for high SYN counts
            if syn_count > 100:
                score = min(score + 0.15, 1.0)
        
        return score
    
    def _trigger_detection_callbacks(self, threat_info: Dict[str, Any]) -> None:
        """Trigger registered detection callbacks.
        
        Args:
            threat_info: Threat information dictionary
        """
        for callback in self.detection_callbacks:
            try:
                callback(threat_info)
            except Exception as e:
                self.logger.log_threat(
                    'error',
                    f'Error in detection callback: {str(e)}',
                    {'error_type': type(e).__name__}
                )
    
    def register_detection_callback(self, callback: Callable[[Dict[str, Any]], None]) -> None:
        """Register a callback for threat detection alerts.
        
        Args:
            callback: Function to call when threat detected
        """
        self.detection_callbacks.append(callback)
    
    def start(self) -> bool:
        """Start NIDS Engine.
        
        Returns:
            True if started successfully, False otherwise
        """
        if self.is_running:
            self.logger.log_threat('warning', 'NIDS Engine is already running')
            return False
        
        if not self.packet_processor:
            if not self.initialize():
                return False
        
        self.is_running = True
        self.stats['start_time'] = datetime.now()
        self.packet_processor.start_sniffing()
        
        self.logger.log_threat('info', 'NIDS Engine started')
        return True
    
    def stop(self) -> None:
        """Stop NIDS Engine."""
        if not self.is_running:
            return
        
        self.is_running = False
        if self.packet_processor:
            self.packet_processor.stop_sniffing()
        
        if self.stats['start_time']:
            uptime = (datetime.now() - self.stats['start_time']).total_seconds()
            self.stats['uptime_seconds'] = uptime
        
        self.logger.log_threat('info', 'NIDS Engine stopped')
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get detection statistics.
        
        Returns:
            Dictionary of statistics
        """
        return self.stats.copy()
    
    def get_active_flows(self) -> Dict[str, Dict[str, Any]]:
        """Get currently active network flows.
        
        Returns:
            Dictionary of active flows
        """
        return self.feature_extractor.get_all_flows()
    
    def clear_statistics(self) -> None:
        """Clear detection statistics."""
        self.stats['packets_processed'] = 0
        self.stats['anomalies_detected'] = 0
        self.stats['alerts_raised'] = 0
        self.stats['threats_identified'] = []
        self.logger.log_threat('info', 'Statistics cleared')
