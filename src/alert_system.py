"""Alert System Module for NIDS

Handles generation, management, and delivery of security alerts.
Supports multiple notification channels (email, webhook, syslog, etc.)
"""

from typing import Dict, List, Optional, Any, Callable
from datetime import datetime
from enum import Enum
import json

from .logger import ThreatLogger


class AlertSeverity(Enum):
    """Alert severity levels."""
    LOW = 'low'
    MEDIUM = 'medium'
    HIGH = 'high'
    CRITICAL = 'critical'


class AlertStatus(Enum):
    """Alert status."""
    OPEN = 'open'
    ACKNOWLEDGED = 'acknowledged'
    RESOLVED = 'resolved'
    FALSE_POSITIVE = 'false_positive'


class Alert:
    """Represents a security alert."""
    
    def __init__(self, alert_id: str, threat_type: str, severity: AlertSeverity,
                 source_ip: str, destination_ip: str, description: str,
                 threat_details: Dict[str, Any]):
        """
        Initialize alert.
        
        Args:
            alert_id: Unique alert identifier
            threat_type: Type of threat detected
            severity: Severity level of the alert
            source_ip: Source IP of the threat
            destination_ip: Destination IP of the threat
            description: Human-readable description
            threat_details: Additional threat details
        """
        self.alert_id = alert_id
        self.threat_type = threat_type
        self.severity = severity
        self.source_ip = source_ip
        self.destination_ip = destination_ip
        self.description = description
        self.threat_details = threat_details
        self.created_at = datetime.now()
        self.status = AlertStatus.OPEN
        self.acknowledged_at: Optional[datetime] = None
        self.resolved_at: Optional[datetime] = None
        self.response_actions: List[str] = []
    
    def acknowledge(self, analyst: str) -> None:
        """Acknowledge the alert.
        
        Args:
            analyst: Name of analyst acknowledging the alert
        """
        self.status = AlertStatus.ACKNOWLEDGED
        self.acknowledged_at = datetime.now()
        self.response_actions.append(f'Acknowledged by {analyst}')
    
    def resolve(self, resolution: str) -> None:
        """Mark alert as resolved.
        
        Args:
            resolution: Resolution details
        """
        self.status = AlertStatus.RESOLVED
        self.resolved_at = datetime.now()
        self.response_actions.append(f'Resolved: {resolution}')
    
    def mark_false_positive(self, reason: str) -> None:
        """Mark alert as false positive.
        
        Args:
            reason: Reason for false positive classification
        """
        self.status = AlertStatus.FALSE_POSITIVE
        self.response_actions.append(f'False positive: {reason}')
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert alert to dictionary.
        
        Returns:
            Dictionary representation of alert
        """
        return {
            'alert_id': self.alert_id,
            'threat_type': self.threat_type,
            'severity': self.severity.value,
            'source_ip': self.source_ip,
            'destination_ip': self.destination_ip,
            'description': self.description,
            'created_at': self.created_at.isoformat(),
            'status': self.status.value,
            'acknowledged_at': self.acknowledged_at.isoformat() if self.acknowledged_at else None,
            'resolved_at': self.resolved_at.isoformat() if self.resolved_at else None,
            'response_actions': self.response_actions,
            'threat_details': self.threat_details,
        }


class AlertNotificationChannel:
    """Base class for alert notification channels."""
    
    def __init__(self, name: str):
        """
        Initialize notification channel.
        
        Args:
            name: Channel name
        """
        self.name = name
        self.logger = ThreatLogger()
        self.is_enabled = True
    
    def send(self, alert: Alert) -> bool:
        """Send alert notification.
        
        Args:
            alert: Alert to send
            
        Returns:
            True if sent successfully, False otherwise
        """
        raise NotImplementedError


class EmailAlertChannel(AlertNotificationChannel):
    """Email-based alert notification."""
    
    def __init__(self, smtp_server: str, smtp_port: int, recipients: List[str]):
        """
        Initialize email alert channel.
        
        Args:
            smtp_server: SMTP server address
            smtp_port: SMTP server port
            recipients: Email recipients
        """
        super().__init__('Email')
        self.smtp_server = smtp_server
        self.smtp_port = smtp_port
        self.recipients = recipients
    
    def send(self, alert: Alert) -> bool:
        """Send alert via email.
        
        Args:
            alert: Alert to send
            
        Returns:
            True if sent successfully
        """
        try:
            # Placeholder for actual email sending
            # In real implementation, use smtplib
            self.logger.log_threat(
                'info',
                f'Email alert sent for {alert.threat_type}',
                {'recipients': self.recipients, 'alert_id': alert.alert_id}
            )
            return True
        except Exception as e:
            self.logger.log_threat(
                'error',
                f'Failed to send email alert: {str(e)}',
                {'error_type': type(e).__name__}
            )
            return False


class WebhookAlertChannel(AlertNotificationChannel):
    """Webhook-based alert notification."""
    
    def __init__(self, webhook_url: str):
        """
        Initialize webhook alert channel.
        
        Args:
            webhook_url: Webhook URL for notifications
        """
        super().__init__('Webhook')
        self.webhook_url = webhook_url
    
    def send(self, alert: Alert) -> bool:
        """Send alert via webhook.
        
        Args:
            alert: Alert to send
            
        Returns:
            True if sent successfully
        """
        try:
            # Placeholder for actual webhook sending
            # In real implementation, use requests library
            payload = json.dumps(alert.to_dict())
            self.logger.log_threat(
                'info',
                f'Webhook alert sent for {alert.threat_type}',
                {'webhook_url': self.webhook_url, 'alert_id': alert.alert_id}
            )
            return True
        except Exception as e:
            self.logger.log_threat(
                'error',
                f'Failed to send webhook alert: {str(e)}',
                {'error_type': type(e).__name__}
            )
            return False


class AlertManager:
    """Manages alerts and notification channels."""
    
    def __init__(self):
        """Initialize alert manager."""
        self.logger = ThreatLogger()
        self.alerts: Dict[str, Alert] = {}
        self.channels: List[AlertNotificationChannel] = []
        self.alert_counter = 0
    
    def add_notification_channel(self, channel: AlertNotificationChannel) -> None:
        """Add notification channel.
        
        Args:
            channel: AlertNotificationChannel instance
        """
        self.channels.append(channel)
        self.logger.log_threat(
            'info',
            f'Added notification channel: {channel.name}'
        )
    
    def create_alert(self, threat_type: str, severity: AlertSeverity,
                    source_ip: str, destination_ip: str,
                    description: str, threat_details: Dict[str, Any]) -> Alert:
        """Create and register a new alert.
        
        Args:
            threat_type: Type of threat
            severity: Alert severity
            source_ip: Source IP
            destination_ip: Destination IP
            description: Alert description
            threat_details: Additional details
            
        Returns:
            Created Alert instance
        """
        self.alert_counter += 1
        alert_id = f'ALERT-{self.alert_counter:06d}'
        
        alert = Alert(
            alert_id=alert_id,
            threat_type=threat_type,
            severity=severity,
            source_ip=source_ip,
            destination_ip=destination_ip,
            description=description,
            threat_details=threat_details
        )
        
        self.alerts[alert_id] = alert
        
        # Send notifications
        self._notify_channels(alert)
        
        self.logger.log_threat(
            'warning',
            f'Alert created: {threat_type}',
            alert.to_dict()
        )
        
        return alert
    
    def _notify_channels(self, alert: Alert) -> None:
        """Send alert to all notification channels.
        
        Args:
            alert: Alert to send
        """
        for channel in self.channels:
            if channel.is_enabled:
                try:
                    channel.send(alert)
                except Exception as e:
                    self.logger.log_threat(
                        'error',
                        f'Error notifying via {channel.name}: {str(e)}',
                        {'error_type': type(e).__name__}
                    )
    
    def get_alert(self, alert_id: str) -> Optional[Alert]:
        """Get alert by ID.
        
        Args:
            alert_id: Alert identifier
            
        Returns:
            Alert if found, None otherwise
        """
        return self.alerts.get(alert_id)
    
    def get_open_alerts(self) -> List[Alert]:
        """Get all open alerts.
        
        Returns:
            List of open alerts
        """
        return [a for a in self.alerts.values() if a.status == AlertStatus.OPEN]
    
    def get_alerts_by_severity(self, severity: AlertSeverity) -> List[Alert]:
        """Get alerts by severity.
        
        Args:
            severity: Alert severity
            
        Returns:
            List of matching alerts
        """
        return [a for a in self.alerts.values() if a.severity == severity]
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get alert statistics.
        
        Returns:
            Dictionary with alert statistics
        """
        return {
            'total_alerts': len(self.alerts),
            'open_alerts': len(self.get_open_alerts()),
            'critical_alerts': len(self.get_alerts_by_severity(AlertSeverity.CRITICAL)),
            'high_alerts': len(self.get_alerts_by_severity(AlertSeverity.HIGH)),
            'medium_alerts': len(self.get_alerts_by_severity(AlertSeverity.MEDIUM)),
            'low_alerts': len(self.get_alerts_by_severity(AlertSeverity.LOW)),
        }
