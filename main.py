#!/usr/bin/env python3
"""
Network Intrusion Detection System (NIDS)
Advanced ML-based cybersecurity project for real-time network monitoring and intrusion detection

Author: Cybersecurity Team
Version: 1.0.0
"""

import sys
import argparse
import logging
from pathlib import Path

# Add src directory to path
sys.path.insert(0, str(Path(__file__).parent / 'src'))

from src.config import Config
from src.nids_engine import NIDSEngine
from src.web.app import create_app
from src.logger import setup_logger


def setup_argparse():
    """Setup command-line argument parser"""
    parser = argparse.ArgumentParser(
        description='Network Intrusion Detection System (NIDS)'
    )
    
    parser.add_argument(
        '--mode',
        choices=['detection', 'training', 'api'],
        default='detection',
        help='Operating mode: detection (sniff), training (ML), or api (web)'
    )
    
    parser.add_argument(
        '--config',
        type=str,
        default='config/nids_config.yaml',
        help='Path to configuration file'
    )
    
    parser.add_argument(
        '--interface',
        type=str,
        default=None,
        help='Network interface to monitor (e.g., eth0, wlan0)'
    )
    
    parser.add_argument(
        '--log-level',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
        default='INFO',
        help='Logging level'
    )
    
    parser.add_argument(
        '--model',
        type=str,
        default='models/nids_model.pkl',
        help='Path to trained ML model'
    )
    
    return parser.parse_args()


def main():
    """Main entry point"""
    args = setup_argparse()
    
    # Setup logger
    logger = setup_logger('NIDS', level=getattr(logging, args.log_level))
    logger.info("=" * 60)
    logger.info("Network Intrusion Detection System (NIDS) v1.0.0")
    logger.info("=" * 60)
    
    # Load configuration
    config = Config(args.config)
    logger.info(f"Configuration loaded from: {args.config}")
    
    try:
        if args.mode == 'detection':
            # Start real-time intrusion detection
            logger.info("Starting NIDS in DETECTION mode...")
            engine = NIDSEngine(config, args.model, args.interface)
            engine.start_monitoring()
            
        elif args.mode == 'training':
            # Train ML model
            logger.info("Starting NIDS in TRAINING mode...")
            from src.ml.trainer import ModelTrainer
            trainer = ModelTrainer(config)
            trainer.train_model()
            
        elif args.mode == 'api':
            # Start web API and dashboard
            logger.info("Starting NIDS in API mode...")
            app = create_app(config)
            app.run(host='0.0.0.0', port=5000, debug=False)
    
    except KeyboardInterrupt:
        logger.info("Shutting down gracefully...")
        sys.exit(0)
    except Exception as e:
        logger.critical(f"Fatal error: {str(e)}", exc_info=True)
        sys.exit(1)


if __name__ == '__main__':
    main()
