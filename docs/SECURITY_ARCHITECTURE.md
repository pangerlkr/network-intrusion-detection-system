# Security Architecture

This document describes the security architecture, trust boundaries, and key risks of the Network Intrusion Detection System (NIDS) project.

The goal is to provide transparency about what the system does, where it runs, and what assumptions it makes, so that users and contributors can deploy and extend it safely.

---

## High-Level Components

The system consists of several major components:

- **Packet capture and preprocessing**
  - Captures live traffic from network interfaces using Scapy.
  - Extracts relevant fields and normalizes them for feature extraction.

- **Feature extraction and ML detection**
  - Builds flow- and packet-level features in `feature_extractor.py`.
  - Runs ML models (Random Forest, Isolation Forest, neural networks, XGBoost) in the NIDS engine.

- **Detection engines**
  - Signature/rule-based detection in `src/detection/rule_engine.py`.
  - Anomaly detection in `src/detection/anomaly_detector.py`.

- **Alerting**
  - Dispatches alerts through email, Slack, Syslog, and other channels via `src/alerts/`.

- **Web API and dashboard**
  - Flask API (`web/app.py`, `web/routes.py`) and frontend (React/JS in `web/static/`) for monitoring and configuration.
  - Optional PostgreSQL backend for logging and audit trails.

---

## Trust Boundaries and Deployment Model

Typical deployment:

- **Sensor / NIDS engine host**
  - Runs packet capture and detection logic.
  - Requires elevated privileges for raw socket access.

- **Management / dashboard**
  - Runs the Flask API and web UI.
  - May run on the same host (lab) or a separate management host (production-style).

- **Data stores and external services**
  - PostgreSQL database for logs.
  - Email/Slack/Syslog endpoints for alerts.

Trust assumptions:

- The host running packet capture is under administrative control of the defender.
- The management interface (dashboard) is reachable only from trusted operator networks.
- Secrets (API keys, SMTP passwords, Slack webhooks) are not checked into source control and are stored in environment variables or external secret stores.

---

## Attack Surface

Key externally exposed surfaces:

- **Web dashboard and API**
  - HTTP endpoints served by Flask.
  - Potential risk of authentication bypass, injection, or CSRF if deployed without hardening.

- **Alerting integrations**
  - Outbound connections to SMTP, Slack webhooks, Syslog servers.
  - Misconfiguration could leak sensitive data to unintended destinations.

- **Model and configuration files**
  - ML model files (`models/nids_model.pkl`, `scaler.pkl`).
  - Configuration files under `config/`, including alert endpoints and thresholds.

- **Packet capture interface**
  - Raw access to network traffic; compromise of the NIDS engine could expose captured data.

---

## Authentication and Authorization (Current Status)

Current minimal baseline:

- The Flask API and dashboard are intended for trusted environments and may not yet enforce strong authentication/authorization by default.
- Some deployments may rely on external controls (reverse proxy with auth, VPN access, IP allowlists).

Recommended improvements (high-level roadmap):

- Add JWT-based authentication for API endpoints (login endpoint → issue token → verify on each protected route).
- Implement role-based access:
  - Admin: configuration changes, model updates, rule management.
  - Analyst: read-only access to alerts, dashboards, and logs.
- Enforce HTTPS/TLS termination in front of the Flask app (reverse proxy such as Nginx/Caddy or platform TLS).

---

## Data Handling and Privacy

The NIDS may see and process sensitive data in packets.

Guidelines and recommendations:

- Prefer **header- and flow-level features** over full payload storage whenever possible.
- If packet payloads are captured or stored:
  - Treat PCAPs as sensitive data.
  - Restrict access and apply encryption at rest.
- Anonymize or pseudonymize:
  - IP addresses and hostnames where feasible.
  - Application-layer identifiers when not needed for detection.

When logging to PostgreSQL:

- Limit sensitive fields stored (focus on metadata and detection results).
- Use TLS for DB connections when running over untrusted networks.
- Consider retention policies and regularly purge old data.

---

## Hardening Recommendations

For more secure deployments:

- **Process isolation**
  - Run the packet capture component with the minimum capabilities required (e.g., Linux capabilities instead of full root where possible).
  - Consider containerizing components and using network policies.

- **Network exposure**
  - Bind the Flask API to localhost or internal interfaces by default.
  - Use a reverse proxy with TLS and authentication if exposing to other networks.

- **Configuration**
  - Store secrets (SMTP credentials, Slack webhooks, JWT secrets) in environment variables or secret managers rather than in the repo.
  - Validate configuration files at startup and fail fast on insecure defaults.

- **Logging and monitoring**
  - Log access to the dashboard and key configuration actions.
  - Monitor the NIDS system itself for anomalies and tampering.

---

## Limitations and Future Work

Current limitations:

- Not production-hardened by default; primarily intended for educational and lab environments.
- Authentication and authorization for the dashboard/API may be minimal or absent in some configurations.
- Performance and accuracy metrics are dataset-dependent and may not generalize to all environments.

Planned improvements:

- Stronger authN/Z for the API and UI.
- More detailed threat modeling linking MITRE ATT&CK techniques to specific detections (see `docs/THREAT_MODELS.md`).
- Better defaults for secure deployment (TLS, stricter configs, safer logging).

For more detailed attack scenarios and mappings, refer to `docs/THREAT_MODELS.md`.
