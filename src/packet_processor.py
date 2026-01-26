"""Packet Processing Module for NIDS

Handles network packet capture, parsing, and processing using Scapy.
Provides interface for extracting network features from captured packets.
"""

import threading
from typing import Callable, Optional, List, Dict, Any
from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime

from .logger import ThreatLogger


class PacketProcessor:
    """Processes network packets and extracts relevant features."""
    
    def __init__(self, interface: Optional[str] = None, packet_count: int = 0):
        """
        Initialize packet processor.
        
        Args:
            interface: Network interface to sniff on (None = all)
            packet_count: Max packets to capture (0 = unlimited)
        """
        self.interface = interface
        self.packet_count = packet_count
        self.logger = ThreatLogger()
        self.packets: List[Dict[str, Any]] = []
        self.is_running = False
        self.sniffer_thread: Optional[threading.Thread] = None
        self.packet_callback: Optional[Callable] = None
    
    def set_packet_callback(self, callback: Callable[[Dict[str, Any]], None]) -> None:
        """Set callback function for each captured packet.
        
        Args:
            callback: Function to call with packet data dict
        """
        self.packet_callback = callback
    
    def _parse_packet(self, packet) -> Dict[str, Any]:
        """Parse Scapy packet into feature dictionary.
        
        Args:
            packet: Scapy packet object
            
        Returns:
            Dictionary with extracted packet features
        """
        packet_data = {
            'timestamp': datetime.now().isoformat(),
            'src_ip': None,
            'dst_ip': None,
            'src_port': None,
            'dst_port': None,
            'protocol': None,
            'payload_size': 0,
            'flags': [],
            'raw_packet': packet
        }
        
        if IP in packet:
            packet_data['src_ip'] = packet[IP].src
            packet_data['dst_ip'] = packet[IP].dst
            packet_data['payload_size'] = packet[IP].len
            
            if TCP in packet:
                packet_data['src_port'] = packet[TCP].sport
                packet_data['dst_port'] = packet[TCP].dport
                packet_data['protocol'] = 'TCP'
                flags = []
                if packet[TCP].flags.F:
                    flags.append('FIN')
                if packet[TCP].flags.S:
                    flags.append('SYN')
                if packet[TCP].flags.R:
                    flags.append('RST')
                if packet[TCP].flags.A:
                    flags.append('ACK')
                packet_data['flags'] = flags
                
            elif UDP in packet:
                packet_data['src_port'] = packet[UDP].sport
                packet_data['dst_port'] = packet[UDP].dport
                packet_data['protocol'] = 'UDP'
                
            elif ICMP in packet:
                packet_data['protocol'] = 'ICMP'
                packet_data['dst_ip'] = packet[IP].dst
        
        return packet_data
    
    def _packet_sniffer_callback(self, packet) -> None:
        """Callback for scapy sniff function.
        
        Args:
            packet: Captured packet from scapy
        """
        try:
            parsed_packet = self._parse_packet(packet)
            self.packets.append(parsed_packet)
            
            if self.packet_callback:
                self.packet_callback(parsed_packet)
                
        except Exception as e:
            self.logger.log_threat(
                'error', 
                f'Error processing packet: {str(e)}',
                {'error_type': type(e).__name__}
            )
    
    def start_sniffing(self) -> None:
        """Start packet sniffing in background thread."""
        if self.is_running:
            return
        
        self.is_running = True
        self.sniffer_thread = threading.Thread(
            target=self._sniff_packets,
            daemon=True
        )
        self.sniffer_thread.start()
        self.logger.log_threat(
            'info',
            f'Started packet sniffing on interface: {self.interface or "all"}'
        )
    
    def _sniff_packets(self) -> None:
        """Internal method to sniff packets."""
        try:
            sniff(
                iface=self.interface,
                prn=self._packet_sniffer_callback,
                store=False,
                count=self.packet_count if self.packet_count > 0 else 0
            )
        except Exception as e:
            self.logger.log_threat(
                'error',
                f'Sniffing error: {str(e)}',
                {'error_type': type(e).__name__}
            )
        finally:
            self.stop_sniffing()
    
    def stop_sniffing(self) -> None:
        """Stop packet sniffing."""
        self.is_running = False
        if self.sniffer_thread:
            self.sniffer_thread.join(timeout=2)
        self.logger.log_threat('info', 'Stopped packet sniffing')
    
    def get_packets(self) -> List[Dict[str, Any]]:
        """Get all captured packets.
        
        Returns:
            List of parsed packet dictionaries
        """
        return self.packets.copy()
    
    def clear_packets(self) -> None:
        """Clear packet buffer."""
        self.packets.clear()
    
    def get_packet_count(self) -> int:
        """Get number of captured packets.
        
        Returns:
            Count of packets in buffer
        """
        return len(self.packets)
