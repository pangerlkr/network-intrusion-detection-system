---
layout: default
title: Network Intrusion Detection System (NIDS)
---

# Network Intrusion Detection System (NIDS)

An ML-powered, real-time Network Intrusion Detection System with advanced packet analysis, anomaly detection, and a modern web-based monitoring dashboard.

## Key Features

- **Real-Time Packet Capture & Analysis**
  - Live traffic monitoring using Scapy
  - Multi-protocol support (TCP, UDP, ICMP, DNS)
  - High-performance packet processing

- **Machine Learning-Based Detection**
  - Multiple algorithms: Random Forest, Isolation Forest, XGBoost, Neural Networks
  - Anomaly detection with configurable thresholds
  - Flow-level and packet-level feature extraction

- **Signature & Rule-Based Detection**
  - Internal rule engine with protocol-level matching
  - Support for custom detection rules
  - Extensible rule format

- **Intelligent Alerting**
  - Multi-channel notifications: Email, Slack, Syslog
  - Customizable alert severity levels
  - Rich alert enrichment with metadata

- **Web Dashboard & API**
  - Real-time alert monitoring
  - System status and metrics visualization
  - RESTful API for programmatic access
  - PostgreSQL audit logging

- **Production-Ready Architecture**
  - Modular, extensible codebase
  - Docker-ready deployment
  - Comprehensive documentation
  - Security-focused design

## Quick Start

### Installation

```bash
git clone https://github.com/pangerlkr/network-intrusion-detection-system.git
cd network-intrusion-detection-system
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### Run Detection Mode

```bash
sudo python main.py --mode detection --interface eth0 --log-level INFO
```

### Start Dashboard

```bash
python main.py --mode api --log-level INFO
# Visit http://localhost:5000
```

### Train Models

```bash
python main.py --mode training --log-level DEBUG
```

## Documentation

- **[Architecture](docs/ARCHITECTURE.md)** - System design and components
- **[Installation Guide](docs/INSTALLATION.md)** - Setup and configuration
- **[Security Architecture](docs/SECURITY_ARCHITECTURE.md)** - Security considerations and hardening
- **[Operations Runbook](docs/OPERATIONS.md)** - Day-to-day operations and troubleshooting
- **[API Documentation](docs/API_DOCUMENTATION.md)** - REST API endpoints and usage
- **[Threat Models](docs/THREAT_MODELS.md)** - MITRE ATT&CK mappings
- **[Contributing Guide](CONTRIBUTING.md)** - How to contribute to the project

## Project Goals

This NIDS project aims to be:

- ✅ A realistic, educational codebase for security students and professionals
- ✅ A flexible platform for ML-based intrusion detection research
- ✅ A reusable engine for integration into other security tools
- ✅ A reference implementation for defense-in-depth strategies

## Performance Metrics

- Detection Accuracy: ~96% on KDD99 and UNSW-NB15 datasets
- False Positive Rate: <2% (tunable)
- Packet Processing: 100K+ packets/second
- Detection Latency: <100ms (typical)

*Note: Metrics are dataset-dependent and may vary based on network environment and configuration.*

## Use Cases

- **Security Research & Education**
  - Teaching ML-based security concepts
  - Capstone projects and thesis work
  - Security operations training

- **Lab & POC Environments**
  - Internal network monitoring
  - Threat simulation and testing
  - Security tool evaluation

- **Production Deployment (with hardening)**
  - Enterprise network monitoring
  - Critical infrastructure protection
  - Compliance and audit logging

## Architecture Overview

```
Packet Capture (Scapy)
       ↓
Feature Extraction
       ↓
┌─────────────────────────────────┐
│  Detection Engines              │
│  ├─ ML Models (Random Forest)   │
│  ├─ Anomaly Detection           │
│  └─ Rule Engine                 │
└──────────────────┬──────────────┘
                   ↓
           Alert Enrichment
                   ↓
┌─────────────────────────────────┐
│  Alerting Channels              │
│  ├─ Email                       │
│  ├─ Slack                       │
│  ├─ Syslog                      │
│  └─ PostgreSQL Logging          │
└─────────────────────────────────┘
                   ↓
           Dashboard & API
```

## Technology Stack

- **Language**: Python 3.8+
- **Packet Capture**: Scapy
- **ML Framework**: scikit-learn, TensorFlow/Keras
- **Web Framework**: Flask
- **Database**: PostgreSQL
- **Frontend**: React/JavaScript
- **Deployment**: Docker, Render, Netlify

## Contributing

Contributions are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for:

- How to get started
- Code style and formatting guidelines
- Testing requirements
- Pull request process
- Good first issues to tackle

## Security Considerations

This is an **educational and lab-grade** project. For production deployments:

- See [SECURITY_ARCHITECTURE.md](docs/SECURITY_ARCHITECTURE.md) for detailed security guidance
- Implement proper authentication and authorization
- Use TLS for all external communication
- Apply appropriate network segmentation
- Monitor and log all system activities
- Keep dependencies updated

## License

MIT License - See LICENSE file for details

## Contact & Support

- **GitHub Issues**: Report bugs or request features
- **Email**: contact@pangerlkr.link
- **Repository**: [pangerlkr/network-intrusion-detection-system](https://github.com/pangerlkr/network-intrusion-detection-system)

---

**Last Updated**: January 2026  
**Project Status**: Active Development
