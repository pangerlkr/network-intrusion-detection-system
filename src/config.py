"""
Configuration Management Module
Handles loading and validating NIDS configuration from YAML files
"""

import yaml
import os
from pathlib import Path
from typing import Dict, Any, Optional


class Config:
    """Configuration management class for NIDS"""
    
    DEFAULT_CONFIG = {
        'network': {
            'interfaces': ['eth0'],
            'packet_filter': '',
            'snapshot_len': 65535,
            'timeout': 1000,
        },
        'detection': {
            'model_path': 'models/nids_model.pkl',
            'scaler_path': 'models/scaler.pkl',
            'threshold': 0.7,
            'algorithms': ['random_forest', 'isolation_forest'],
        },
        'alerts': {
            'enabled': True,
            'email': {
                'enabled': False,
                'server': 'smtp.gmail.com',
                'port': 587,
                'from': 'alerts@nids.local',
                'to': [],
            },
            'slack': {
                'enabled': False,
                'webhook_url': '',
            },
            'syslog': {
                'enabled': False,
                'server': 'localhost',
                'port': 514,
            },
        },
        'logging': {
            'level': 'INFO',
            'directory': 'logs',
            'max_file_size': 10485760,  # 10MB
        },
        'database': {
            'enabled': False,
            'type': 'postgresql',
            'host': 'localhost',
            'port': 5432,
            'name': 'nids_db',
            'user': 'nids',
        },
    }
    
    def __init__(self, config_path: str = 'config/nids_config.yaml'):
        """
        Initialize configuration from file or use defaults
        
        Args:
            config_path (str): Path to YAML configuration file
        """
        self.config_path = config_path
        self.config = self.DEFAULT_CONFIG.copy()
        
        if os.path.exists(config_path):
            self._load_from_file(config_path)
        else:
            self._create_default_config(config_path)
    
    def _load_from_file(self, path: str) -> None:
        """Load configuration from YAML file"""
        try:
            with open(path, 'r') as f:
                file_config = yaml.safe_load(f) or {}
            self._merge_configs(self.config, file_config)
        except Exception as e:
            print(f"Error loading config file {path}: {e}. Using defaults.")
    
    def _create_default_config(self, path: str) -> None:
        """Create default config file"""
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        try:
            with open(path, 'w') as f:
                yaml.dump(self.DEFAULT_CONFIG, f, default_flow_style=False)
        except Exception as e:
            print(f"Error creating default config: {e}")
    
    @staticmethod
    def _merge_configs(base: Dict, override: Dict) -> None:
        """Recursively merge override config into base"""
        for key, value in override.items():
            if isinstance(value, dict) and key in base:
                Config._merge_configs(base[key], value)
            else:
                base[key] = value
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get config value by dot-notation key (e.g., 'network.interfaces')"""
        keys = key.split('.')
        value = self.config
        try:
            for k in keys:
                value = value[k]
            return value
        except (KeyError, TypeError):
            return default
    
    def set(self, key: str, value: Any) -> None:
        """Set config value by dot-notation key"""
        keys = key.split('.')
        config = self.config
        for k in keys[:-1]:
            config = config.setdefault(k, {})
        config[keys[-1]] = value
    
    def save(self, path: Optional[str] = None) -> None:
        """Save configuration to YAML file"""
        save_path = path or self.config_path
        try:
            Path(save_path).parent.mkdir(parents=True, exist_ok=True)
            with open(save_path, 'w') as f:
                yaml.dump(self.config, f, default_flow_style=False)
        except Exception as e:
            print(f"Error saving config: {e}")
    
    def __repr__(self) -> str:
        return f"Config({self.config_path})"
    
    def __str__(self) -> str:
        return yaml.dump(self.config, default_flow_style=False)


def load_config(config_path: str = 'config/nids_config.yaml') -> Config:
    """
    Load and return a Config instance.
    
    This function provides a simple interface for loading configuration
    from a YAML file or using default configuration.
    
    Args:
        config_path (str): Path to YAML configuration file
        
    Returns:
        Config: Configured Config instance ready for use
    """
    return Config(config_path)
