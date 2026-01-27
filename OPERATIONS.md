# Operations Guide (Runbook)

This document provides practical guidance for running, monitoring, and troubleshooting the Network Intrusion Detection System (NIDS) in day-to-day operations. [page:1]

---

## Operating Modes

The main entry point is `main.py`, which supports multiple modes: detection, training, and API. [page:1]

### Real-Time Detection Mode

Run real-time detection on a network interface (requires elevated privileges): [page:1]

```bash
sudo python main.py --mode detection --interface eth0 --log-level INFO
```

Key behaviors:

- Captures packets from the specified interface.
- Extracts features and runs ML and rule-based detection.
- Sends alerts via configured channels (email, Slack, Syslog) and optionally logs to PostgreSQL. [page:1]

### Model Training Mode

Train or retrain ML models on the configured dataset: [page:1]

```bash
python main.py --mode training --log-level DEBUG
```

This will:

- Load training data (e.g., `data/training_data.csv`).
- Run the training pipeline in `src/ml/trainer.py`.
- Save updated model artifacts under `models/` (e.g., `nids_model.pkl`, `scaler.pkl`). [page:1]

### Web Dashboard / API Mode

Start the Flask API server and dashboard: [page:1]

```bash
python main.py --mode api --log-level INFO
# Visit http://localhost:5000
```

Use this mode for:

- Viewing alerts and system status in the web UI.
- Calling REST API endpoints as described in `docs/API_DOCUMENTATION.md`. [page:1]

---

## Configuration Management

Main configuration file: `config/nids_config.yaml` (and optional overrides like `config/nids_config.local.yaml`). [page:1]

Typical configuration sections:

- **Network**
  - Interfaces to monitor (e.g., `eth0`, `wlan0`).
  - Packet filter expressions (e.g., BPF-style filters for ports/protocols). [page:1]

- **Detection**
  - Model path (e.g., `models/nids_model.pkl`).
  - Thresholds for anomaly scores.
  - Enabled algorithms (Random Forest, Isolation Forest, etc.). [page:1]

- **Alerts**
  - Enable/disable alerting.
  - Email server and from-address.
  - Slack webhook URL, Syslog targets, and other notifier settings. [page:1]

- **Logging**
  - Log level and output (console, file).
  - Database connection (PostgreSQL DSN) if audit logging is enabled. [page:1]

When making changes:

- Keep a backup of the previous config.
- Prefer using a local override file (`nids_config.local.yaml`) that is not committed to version control.

---

## Interpreting Alerts

Alerts typically include: [page:1]

- Timestamp and source/destination IP and port.
- Protocol and basic packet/flow metadata.
- Detection source (e.g., rule engine vs ML model).
- Severity level (e.g., info, warning, critical).
- Detection reason (e.g., rule ID, anomaly score above threshold). [page:1]

Recommended operator actions:

- Correlate the alert with other logs (firewall, host logs, SIEM).
- Check if the source is expected (e.g., known scanner, internal tool).
- Tune thresholds or rules if a pattern is identified as benign but noisy.

To reduce false positives:

- Adjust model thresholds in the detection section of the config.
- Disable or tweak specific rules in the rule engine configuration.
- Add suppression conditions (e.g., whitelisting known internal hosts) where appropriate.

---

## Health Checks and Monitoring

Key health indicators:

- **NIDS process status**
  - Ensure the detection process is running and capturing packets.
- **Alert volume**
  - Sudden spikes or drops may indicate issues (real incidents or misconfiguration).
- **Resource usage**
  - CPU, memory, and disk usage on the NIDS host.
- **Database connectivity**
  - Confirm logs are being written to PostgreSQL when enabled. [page:1]

If Prometheus metrics are enabled (planned/optional):

- Monitor throughput, detection latency, and error rates via your preferred metrics stack. [page:1]

---

## Common Troubleshooting Scenarios

### No Packets Captured

- Check that you are running with sufficient privileges for packet capture.
- Verify the interface name is correct (`ip a` or `ifconfig`).
- Confirm there is actual traffic on the monitored interface.
- Review packet filter expressions in `config/nids_config.yaml` to ensure they are not too restrictive. [page:1]

### No Alerts Generated

- Confirm detection mode is running and that traffic matches monitored protocols/ports.
- Lower anomaly thresholds or enable additional algorithms in the config.
- Check logs for errors in the detection pipeline or model loading. [page:1]

### High False Positive Rate

- Increase detection thresholds or adjust model configuration.
- Add specific whitelists or rule exceptions where appropriate.
- Review features and model assumptions; retrain models with more representative data if needed. [page:1]

### Database / Logging Errors

- Verify PostgreSQL connection parameters in the config (host, port, database, user, password).
- Check network access between NIDS host and the database.
- Inspect database logs for authentication or permission errors. [page:1]

### Dashboard Not Loading

- Confirm `--mode api` is running and listening on the expected host/port.
- Check Flask logs for stack traces or import errors.
- If behind a reverse proxy, verify proxy configuration and TLS setup.

---

## Change Management and Updates

When updating the system:

1. **Backup configuration and models**
   - Save copies of `config/*` and `models/*`. [page:1]

2. **Pull new code and dependencies**
   - `git pull` from the main branch.
   - `pip install -r requirements.txt` in the virtual environment. [page:1]

3. **Run tests** (when available)
   - `pytest`.

4. **Restart services**
   - Restart detection, training, or API processes as needed.

Keep a simple changelog (or rely on Git tags and release notes) so operators know which version is deployed and what changed. [page:1]

---

For detailed architecture and threat scenarios, see `docs/ARCHITECTURE.md` and `docs/THREAT_MODELS.md`. [page:1]
