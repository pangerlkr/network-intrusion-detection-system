"""
Logging Configuration Module for NIDS
Provides centralized logging setup with file and console outputs
"""

import logging
import logging.handlers
import os
from pathlib import Path
from datetime import datetime


def setup_logger(name: str, log_level=logging.INFO, log_dir: str = "logs"):
    """
    Setup logger with console and file handlers
    
    Args:
        name (str): Logger name
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_dir (str): Directory for log files
    
    Returns:
        logging.Logger: Configured logger instance
    """
    # Create logs directory if it doesn't exist
    Path(log_dir).mkdir(parents=True, exist_ok=True)
    
    # Create logger
    logger = logging.getLogger(name)
    logger.setLevel(log_level)
    
    # Prevent duplicate handlers
    if logger.hasHandlers():
        logger.handlers.clear()
    
    # Create formatters
    detailed_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    simple_formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Console Handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(log_level)
    console_handler.setFormatter(simple_formatter)
    logger.addHandler(console_handler)
    
    # File Handler - General logs
    log_file = os.path.join(log_dir, f"nids_{datetime.now().strftime('%Y%m%d')}.log")
    file_handler = logging.handlers.RotatingFileHandler(
        log_file,
        maxBytes=10*1024*1024,  # 10MB
        backupCount=5
    )
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(detailed_formatter)
    logger.addHandler(file_handler)
    
    # File Handler - Errors only
    error_log = os.path.join(log_dir, f"nids_errors_{datetime.now().strftime('%Y%m%d')}.log")
    error_handler = logging.handlers.RotatingFileHandler(
        error_log,
        maxBytes=5*1024*1024,  # 5MB
        backupCount=3
    )
    error_handler.setLevel(logging.ERROR)
    error_handler.setFormatter(detailed_formatter)
    logger.addHandler(error_handler)
    
    return logger


def setup_threat_logger(log_dir: str = "logs"):
    """
    Setup dedicated logger for threat detections
    
    Args:
        log_dir (str): Directory for threat logs
    
    Returns:
        logging.Logger: Threat logger instance
    """
    Path(log_dir).mkdir(parents=True, exist_ok=True)
    
    threat_logger = logging.getLogger('NIDS.THREATS')
    threat_logger.setLevel(logging.INFO)
    
    if threat_logger.hasHandlers():
        threat_logger.handlers.clear()
    
    threat_formatter = logging.Formatter(
        '%(asctime)s - [THREAT] - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    threat_file = os.path.join(log_dir, f"threats_{datetime.now().strftime('%Y%m%d')}.log")
    threat_handler = logging.handlers.RotatingFileHandler(
        threat_file,
        maxBytes=50*1024*1024,  # 50MB
        backupCount=10
    )
    threat_handler.setFormatter(threat_formatter)
    threat_logger.addHandler(threat_handler)
    
    return threat_logger


class ThreatLogger:
    """
    Threat Logger class that provides threat detection logging functionality.
    Wrapper around the standard logger for threat events.
    """
    
    def __init__(self, log_dir: str = "logs"):
        """Initialize ThreatLogger with a dedicated threat logger."""
        self.logger = setup_threat_logger(log_dir)
    
    def log_threat(self, threat_type: str, severity: str, message, details: dict = None):
        """
        Log a threat event.
        
        Args:
            threat_type (str): Type of threat detected
            severity (str): Severity level (LOW, MEDIUM, HIGH, CRITICAL)
            message: Threat description/message (string or dict)
            details (dict, optional): Additional structured details to include
        """
        log_message = f"[{threat_type}] [{severity}] {message}"
        if details:
            log_message += f" | {details}"
        self.logger.warning(log_message)
    
    def log_alert(self, alert_message: str):
        """Log a security alert."""
        self.logger.error(alert_message)
