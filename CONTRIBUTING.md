# Contributing to Network Intrusion Detection System (NIDS)

Thank you for your interest in contributing! This project is an ML-powered Network Intrusion Detection System with real-time packet analysis, anomaly detection, and a web-based monitoring dashboard.

We welcome contributions from security engineers, data scientists, and developers who want to improve open-source network defense tools.

---

## Project Goals

This project aims to be:

- A realistic, educational NIDS codebase for security students and professionals.
- A flexible platform for experimenting with ML-based intrusion detection.
- A reusable engine that can be integrated into other security tools.

We especially welcome pull requests in the following areas:

- **New or improved ML models**
  - Better classifiers or anomaly detectors (e.g., improved Random Forest/XGBoost configs, autoencoders, LSTM/CNN architectures).
  - Feature engineering improvements and model evaluation.

- **Detection and analysis features**
  - New detection logic in `src/detection/` (e.g., additional anomaly strategies, better rule engine logic).
  - Suricata/Snort rule import and mapping to the internal rule engine.
  - Enhanced packet parsing and protocol support in `packet_processor.py`.

- **Alerting and integrations**
  - New alert channels in `src/alerts/notifiers.py` (e.g., Microsoft Teams, webhooks, SIEM integrations).
  - Improved formatting and enrichment of alert payloads.

- **Deployment & Ops**
  - Docker and Docker Compose setups for NIDS engine + dashboard + PostgreSQL.
  - Helm charts or Kubernetes manifests.
  - Improved logging, metrics, and exporting Prometheus metrics.

- **Security & hardening**
  - Authentication and authorization for the web dashboard/API.
  - TLS support and secure configuration defaults.
  - Threat modeling and security hardening documentation.

---

## Getting Started

1. Fork the repository.
2. Clone your fork and create a feature branch:

   ```bash
   git clone https://github.com/<your-username>/network-intrusion-detection-system.git
   cd network-intrusion-detection-system
   git checkout -b feature/my-change
   ```

3. Create and activate a virtual environment, then install dependencies:

   ```bash
   python -m venv venv
   source venv/bin/activate   # On Windows: venv\Scripts\activate

   pip install -r requirements.txt
   ```

4. Configure the NIDS (optional for tests, useful for manual runs):

   ```bash
   cp config/nids_config.yaml config/nids_config.local.yaml
   # edit config/nids_config.local.yaml
   ```

---

## Code Style and Formatting

We use **black** for code formatting and recommend **isort** for import sorting.

Before committing, run:

```bash
black src web
isort src web
```

If you add or modify tests, you can also run these tools on the `tests/` directory once it exists:

```bash
black tests
isort tests
```

---

## Running Tests

A `tests/` directory is planned for unit and integration tests (as described in the README's project architecture section).

Once tests are available, run all tests with:

```bash
pytest
```

Example conventions (to follow when adding tests):

- Place unit tests under `tests/` (e.g., `tests/test_packet_processor.py`, `tests/test_feature_extractor.py`, `tests/test_detector.py`).
- Use descriptive test names and arrange tests as: setup → action → assertion.
- Prefer small, deterministic tests; use sample PCAPs and small CSVs for fixtures.

If your contribution requires new behavior, please add or update tests accordingly.

---

## Good First Issues (Ideas)

If you are looking for a first contribution, here are some starter ideas:

1. **Add Suricata rule import**
   - Implement a parser that reads Suricata (or Snort) rules and maps them into the internal rule engine format in `src/detection/rule_engine.py`.
   - Add sample rule files and a short section in the docs explaining usage.

2. **Add JWT auth to the API**
   - Implement JSON Web Token-based authentication for the Flask API in `web/app.py` and `web/routes.py`.
   - Add configuration options for token secret and expiry in `config/nids_config.yaml`.
   - Update docs to show how to obtain and use a token for protected endpoints.

3. **Add Docker support**
   - Create a `Dockerfile` and optionally a `docker-compose.yml` to run:
     - NIDS engine
     - Flask API + dashboard
     - PostgreSQL (for logging)
   - Document usage in `DEPLOYMENT.md`.

4. **Improve alert channels**
   - Add a new notifier (e.g., Teams, generic webhook) in `src/alerts/notifiers.py`.
   - Add configuration examples for it in `config/nids_config.yaml`.

If you open a PR for one of these, mention "good first issue" in the description.

---

## Pull Request Guidelines

- Keep PRs focused and small when possible.
- Update relevant docs in `docs/` (and `README.md`) if behavior or configuration changes.
- Ensure code is formatted with black and imports are sorted with isort.
- Add or update tests for new functionality.
- Describe:
  - What changed.
  - Why it changed.
  - How to test it.

Thank you again for contributing to this NIDS project!
