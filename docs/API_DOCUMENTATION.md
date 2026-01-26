# API Documentation

The Network Intrusion Detection System (NIDS) provides a RESTful API for real-time monitoring, model management, and system configuration.

## Base URL
`http://localhost:5000/api/v1`

## Authentication
Currently, the API supports basic authentication via environment variables. In production, it is recommended to use JWT-based authentication.

---

## 1. System Status

### Get System Health
Returns the current health status of the NIDS engine and its components.

- **Endpoint**: `GET /status`
- **Response**: `200 OK`
```json
{
  "status": "online",
  "engine": "active",
  "uptime": "12:45:30",
  "components": {
    "packet_processor": "running",
    "ml_engine": "running",
    "database": "connected",
    "alert_system": "enabled"
  }
}
```

---

## 2. Monitoring & Real-time Data

### Get Live Alerts
Retrieve the most recent threat alerts detected by the system.

- **Endpoint**: `GET /alerts`
- **Query Parameters**:
  - `limit`: Number of alerts to return (default: 50)
  - `severity`: Filter by severity (info, low, medium, high, critical)
- **Response**: `200 OK`
```json
[
  {
    "id": "alert_12345",
    "timestamp": "2026-01-20T10:30:00Z",
    "source_ip": "192.168.1.100",
    "dest_ip": "10.0.0.5",
    "protocol": "TCP",
    "attack_type": "Syn Flood",
    "severity": "high",
    "confidence": 0.92,
    "payload_preview": "..."
  }
]
```

### Get Traffic Statistics
Returns real-time network traffic metrics.

- **Endpoint**: `GET /stats/traffic`
- **Response**: `200 OK`
```json
{
  "packets_per_second": 1250,
  "bytes_per_second": 450000,
  "top_protocols": {
    "TCP": "75%",
    "UDP": "20%",
    "ICMP": "5%"
  },
  "active_connections": 150
}
```

---

## 3. Machine Learning Models

### Get Model Information
Retrieve details about the currently active ML model.

- **Endpoint**: `GET /models/active`
- **Response**: `200 OK`
```json
{
  "model_id": "rf_v1.0",
  "type": "Random Forest",
  "accuracy": 0.965,
  "trained_at": "2026-01-15",
  "features_count": 42
}
```

### Trigger Model Retraining
Initiate a background task to retrain the model with new data.

- **Endpoint**: `POST /models/retrain`
- **Payload**:
```json
{
  "dataset_path": "data/new_training_data.csv",
  "algorithm": "xgboost"
}
```
- **Response**: `202 Accepted`

---

## 4. Configuration

### Get Current Config
- **Endpoint**: `GET /config`
- **Response**: `200 OK`

### Update Configuration
- **Endpoint**: `PATCH /config`
- **Payload**:
```json
{
  "detection": {
    "threshold": 0.8
  },
  "alerts": {
    "slack_enabled": false
  }
}
```
- **Response**: `200 OK`

---

## 5. Webhook Integration

### Register Webhook
- **Endpoint**: `POST /webhooks/register`
- **Payload**:
```json
{
  "url": "https://your-app.com/api/nids-webhook",
  "events": ["critical_alert", "system_down"]
}
```
- **Response**: `201 Created`

---

**Last Updated**: January 2026  
**API Version**: 1.0.0
